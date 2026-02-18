package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes client for fetching
// resource metadata (YAMLs for pods, deployments, etc.).
type Client struct {
	clientset *kubernetes.Clientset
}

// NewClient creates a Kubernetes client. Uses in-cluster
// config if available, falls back to kubeconfig.
func NewClient(kubeconfig string) (*Client, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags(
			"",
			kubeconfig,
		)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf(
			"create k8s config: %w",
			err,
		)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf(
			"create k8s clientset: %w",
			err,
		)
	}

	return &Client{clientset: clientset}, nil
}

// Clientset returns the underlying Kubernetes clientset
// for direct API access (e.g., Secret updates).
func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}

// GetResource fetches a Kubernetes resource by type,
// namespace, and name. Returns JSON representation.
func (c *Client) GetResource(
	ctx context.Context,
	resource string,
	namespace string,
	name string,
) ([]byte, error) {
	opts := metav1.GetOptions{}
	listOpts := metav1.ListOptions{}

	switch resource {
	case "pod", "pods":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				Pods(namespace).Get(ctx, name, opts)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			Pods(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "deployment", "deployments":
		if name != "" {
			obj, err := c.clientset.AppsV1().
				Deployments(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.AppsV1().
			Deployments(namespace).List(
			ctx,
			listOpts,
		)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "service", "services":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				Services(namespace).Get(ctx, name, opts)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			Services(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "statefulset", "statefulsets":
		if name != "" {
			obj, err := c.clientset.AppsV1().
				StatefulSets(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.AppsV1().
			StatefulSets(namespace).List(
			ctx,
			listOpts,
		)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "daemonset", "daemonsets":
		if name != "" {
			obj, err := c.clientset.AppsV1().
				DaemonSets(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.AppsV1().
			DaemonSets(namespace).List(
			ctx,
			listOpts,
		)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "configmap", "configmaps":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				ConfigMaps(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			ConfigMaps(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "secret", "secrets":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				Secrets(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			Secrets(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "namespace", "namespaces":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				Namespaces().Get(ctx, name, opts)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			Namespaces().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "node", "nodes":
		if name != "" {
			obj, err := c.clientset.CoreV1().
				Nodes().Get(ctx, name, opts)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.CoreV1().
			Nodes().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "ingress", "ingresses":
		if name != "" {
			obj, err := c.clientset.NetworkingV1().
				Ingresses(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.NetworkingV1().
			Ingresses(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "job", "jobs":
		if name != "" {
			obj, err := c.clientset.BatchV1().
				Jobs(namespace).Get(ctx, name, opts)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.BatchV1().
			Jobs(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "cronjob", "cronjobs":
		if name != "" {
			obj, err := c.clientset.BatchV1().
				CronJobs(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.BatchV1().
			CronJobs(namespace).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	case "replicaset", "replicasets":
		if name != "" {
			obj, err := c.clientset.AppsV1().
				ReplicaSets(namespace).Get(
				ctx,
				name,
				opts,
			)
			if err != nil {
				return nil, err
			}
			return json.Marshal(obj)
		}
		list, err := c.clientset.AppsV1().
			ReplicaSets(namespace).List(
			ctx,
			listOpts,
		)
		if err != nil {
			return nil, err
		}
		return json.Marshal(list)

	default:
		return nil, fmt.Errorf(
			"unsupported resource type: %s",
			resource,
		)
	}
}
