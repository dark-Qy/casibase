// Copyright 2025 The Casibase Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/casibase/casibase/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type ApplicationView struct {
	Services    []ServiceView    `json:"services"`
	Credentials []EnvVariable    `json:"credentials"`
	Deployments []DeploymentView `json:"deployments"`
	Status      string           `json:"status"`
	CreatedTime string           `json:"createdTime"`
	Namespace   string           `json:"namespace"`
}

type ServiceView struct {
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	ClusterIP    string        `json:"clusterIP"`
	ExternalIP   string        `json:"externalIP"`
	Ports        []ServicePort `json:"ports"`
	InternalHost string        `json:"internalHost"`
	ExternalHost string        `json:"externalHost"`
	CreatedTime  string        `json:"createdTime"`
}

type ServicePort struct {
	Name      string `json:"name"`
	Port      int32  `json:"port"`
	NodePort  int32  `json:"nodePort,omitempty"`
	Protocol  string `json:"protocol"`
	AccessURL string `json:"accessUrl,omitempty"`
}

type DeploymentView struct {
	Name          string          `json:"name"`
	Replicas      int32           `json:"replicas"`
	ReadyReplicas int32           `json:"readyReplicas"`
	Containers    []ContainerView `json:"containers"`
	CreatedTime   string          `json:"createdTime"`
	Status        string          `json:"status"`
}

type ContainerView struct {
	Name      string           `json:"name"`
	Image     string           `json:"image"`
	Resources ResourceRequests `json:"resources"`
}

type ResourceRequests struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

type EnvVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// getExternalHost attempts to get k8s server IP first, then falls back to provided host
func getExternalHost(fallbackHost string) string {
	provider, err := GetDefaultKubernetesProvider()
	if err != nil {
		return fallbackHost
	}

	host, err := parseK8sHost(provider.ConfigText)
	if err != nil || host == "" {
		return fallbackHost
	}

	return host
}

// parseK8sHost extracts server host from kubeconfig content
func parseK8sHost(configText string) (string, error) {
	if strings.TrimSpace(configText) == "" {
		return "", fmt.Errorf("kubeconfig content is empty")
	}

	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(configText))
	if err != nil {
		return "", fmt.Errorf("failed to parse kubeconfig: %v", err)
	}

	if config.Host == "" {
		return "", fmt.Errorf("server address not found")
	}

	serverURL, err := url.Parse(config.Host)
	if err != nil {
		return "", fmt.Errorf("failed to parse server URL: %v", err)
	}

	host := serverURL.Hostname()
	if host == "" {
		return "", fmt.Errorf("unable to extract host")
	}

	return host, nil
}

// GetApplicationView retrieves detailed connection information for an application
func GetApplicationView(owner, name string) (*ApplicationView, error) {
	if err := ensureK8sClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize k8s client: %v", err)
	}

	if !k8sClient.connected {
		return nil, fmt.Errorf("k8s client not connected")
	}

	namespace := fmt.Sprintf(NamespaceFormat, strings.ReplaceAll(name, "_", "-"))

	// Check if namespace exists
	ns, err := k8sClient.clientSet.CoreV1().Namespaces().Get(
		context.TODO(), namespace, metav1.GetOptions{},
	)
	if err != nil {
		if errors.IsNotFound(err) {
			return &ApplicationView{
				Services:    []ServiceView{},
				Credentials: []EnvVariable{},
				Deployments: []DeploymentView{},
				Status:      StatusNotDeployed,
				Namespace:   namespace,
			}, nil
		}
		return nil, fmt.Errorf("failed to get namespace: %v", err)
	}

	details := &ApplicationView{
		Services:    []ServiceView{},
		Credentials: []EnvVariable{},
		Deployments: []DeploymentView{},
		Status:      StatusRunning,
		CreatedTime: ns.CreationTimestamp.Format("2006-01-02 15:04:05"),
		Namespace:   namespace,
	}

	nodeIPs, _ := getNodeIPs()

	if services, err := getServices(namespace, nodeIPs); err == nil {
		details.Services = services
	}

	if deployments, err := getDeployments(namespace); err == nil {
		details.Deployments = deployments
	}

	if credentials, err := getCredentials(namespace); err == nil {
		details.Credentials = credentials
	}

	updateURL(owner, name, details.Services)

	return details, nil
}

// getNodeIPs retrieves external or internal IPs of cluster nodes
func getNodeIPs() ([]string, error) {
	nodes, err := k8sClient.clientSet.CoreV1().Nodes().List(
		context.TODO(), metav1.ListOptions{},
	)
	if err != nil {
		return nil, err
	}

	var nodeIPs []string
	for _, node := range nodes.Items {
		// Try external IP first
		for _, addr := range node.Status.Addresses {
			if addr.Type == v1.NodeExternalIP && addr.Address != "" {
				nodeIPs = append(nodeIPs, addr.Address)
				break
			}
		}
		// Fallback to internal IP if no external IP found
		if len(nodeIPs) == 0 {
			for _, addr := range node.Status.Addresses {
				if addr.Type == v1.NodeInternalIP && addr.Address != "" {
					nodeIPs = append(nodeIPs, addr.Address)
					break
				}
			}
		}
	}

	return nodeIPs, nil
}

// getServices retrieves all services in the application namespace with connection details
func getServices(namespace string, nodeIPs []string) ([]ServiceView, error) {
	services, err := k8sClient.clientSet.CoreV1().Services(namespace).List(
		context.TODO(), metav1.ListOptions{},
	)
	if err != nil {
		return nil, err
	}

	var serviceViews []ServiceView
	for _, svc := range services.Items {
		// Skip default kubernetes service
		if svc.Name == "kubernetes" {
			continue
		}

		view := ServiceView{
			Name:         svc.Name,
			Type:         string(svc.Spec.Type),
			ClusterIP:    svc.Spec.ClusterIP,
			Ports:        []ServicePort{},
			CreatedTime:  svc.CreationTimestamp.Format("2006-01-02 15:04:05"),
			InternalHost: fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, namespace),
		}

		// Determine external access based on service type
		var host string
		switch svc.Spec.Type {
		case v1.ServiceTypeLoadBalancer:
			if len(svc.Status.LoadBalancer.Ingress) > 0 {
				ingress := svc.Status.LoadBalancer.Ingress[0]
				if ingress.IP != "" {
					view.ExternalIP = ingress.IP
					host = ingress.IP
				} else if ingress.Hostname != "" {
					host = ingress.Hostname
				}
			}
		case v1.ServiceTypeNodePort:
			if len(nodeIPs) > 0 {
				host = nodeIPs[0]
			}
		}

		view.ExternalHost = getExternalHost(host)

		for _, port := range svc.Spec.Ports {
			servicePort := ServicePort{
				Name:     port.Name,
				Port:     port.Port,
				Protocol: string(port.Protocol),
			}

			if port.NodePort != 0 {
				servicePort.NodePort = port.NodePort
				if view.ExternalHost != "" {
					servicePort.AccessURL = fmt.Sprintf("%s:%d", view.ExternalHost, port.NodePort)
				}
			}

			view.Ports = append(view.Ports, servicePort)
		}

		serviceViews = append(serviceViews, view)
	}

	return serviceViews, nil
}

// getDeployments retrieves all deployments in the application namespace with status
func getDeployments(namespace string) ([]DeploymentView, error) {
	deployments, err := k8sClient.clientSet.AppsV1().Deployments(namespace).List(
		context.TODO(), metav1.ListOptions{},
	)
	if err != nil {
		return nil, err
	}

	var deploymentViews []DeploymentView
	for _, deployment := range deployments.Items {
		view := DeploymentView{
			Name:          deployment.Name,
			Replicas:      *deployment.Spec.Replicas,
			ReadyReplicas: deployment.Status.ReadyReplicas,
			Containers:    []ContainerView{},
			CreatedTime:   deployment.CreationTimestamp.Format("2006-01-02 15:04:05"),
		}

		// Determine deployment status based on ready replicas
		if view.ReadyReplicas == view.Replicas {
			view.Status = "Running"
		} else if view.ReadyReplicas > 0 {
			view.Status = "Partially Ready"
		} else {
			view.Status = "Not Ready"
		}

		for _, container := range deployment.Spec.Template.Spec.Containers {
			containerView := ContainerView{
				Name:  container.Name,
				Image: container.Image,
			}

			if container.Resources.Requests != nil {
				if cpuRequest := container.Resources.Requests[v1.ResourceCPU]; !cpuRequest.IsZero() {
					containerView.Resources.CPU = cpuRequest.String()
				}
				if memoryRequest := container.Resources.Requests[v1.ResourceMemory]; !memoryRequest.IsZero() {
					containerView.Resources.Memory = memoryRequest.String()
				}
			}

			view.Containers = append(view.Containers, containerView)
		}

		deploymentViews = append(deploymentViews, view)
	}

	return deploymentViews, nil
}

// getCredentials extracts environment variables containing sensitive information
func getCredentials(namespace string) ([]EnvVariable, error) {
	deployments, err := k8sClient.clientSet.AppsV1().Deployments(namespace).List(
		context.TODO(), metav1.ListOptions{},
	)
	if err != nil {
		return nil, err
	}

	credentialKeywords := []string{
		"PASSWORD", "PASS", "SECRET", "KEY", "TOKEN", "AUTH",
		"USER", "USERNAME", "LOGIN", "CREDENTIAL", "DATABASE_URL",
		"DB_PASSWORD", "DB_USER", "ADMIN_PASSWORD", "ROOT_PASSWORD",
	}

	var credentials []EnvVariable
	for _, deployment := range deployments.Items {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			for _, env := range container.Env {
				envNameUpper := strings.ToUpper(env.Name)
				isCredential := false

				// Check if env var name contains credential keywords
				for _, keyword := range credentialKeywords {
					if strings.Contains(envNameUpper, keyword) {
						isCredential = true
						break
					}
				}

				if isCredential {
					value := env.Value
					if env.ValueFrom != nil {
						if env.ValueFrom.SecretKeyRef != nil {
							value = fmt.Sprintf("Secret: %s.%s", env.ValueFrom.SecretKeyRef.Name, env.ValueFrom.SecretKeyRef.Key)
						} else if env.ValueFrom.ConfigMapKeyRef != nil {
							value = fmt.Sprintf("ConfigMap: %s.%s", env.ValueFrom.ConfigMapKeyRef.Name, env.ValueFrom.ConfigMapKeyRef.Key)
						}
					}

					credentials = append(credentials, EnvVariable{
						Name:  env.Name,
						Value: value,
					})
				}
			}
		}
	}

	return credentials, nil
}

// updateURL updates application access URL with first available service endpoint
func updateURL(owner, name string, services []ServiceView) {
	var URL string
	for _, service := range services {
		for _, port := range service.Ports {
			if port.AccessURL != "" {
				URL = port.AccessURL
				break
			}
		}
		if URL != "" {
			break
		}
	}

	if URL != "" {
		if app, err := getApplication(owner, name); err == nil && app != nil {
			app.URL = URL
			if _, err := UpdateApplication(util.GetIdFromOwnerAndName(owner, name), app); err != nil {
				// Log error but don't fail the main operation
				fmt.Printf("Failed to update application access URL: %v\n", err)
			}
		}
	}
}
