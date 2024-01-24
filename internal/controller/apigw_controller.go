/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/scc-digitalhub/apigw-operator/api/v1"
)

const envEnableTls = "ENABLE_TLS"
const envTlsSecretName = "TLS_SECRET_NAME"
const genericStatusUpdateFailedMessage = "failed to update ApiGw status"

// Definitions to manage status conditions
const (
	// Launch deployment and service
	typeInitializing = "Initializing"

	typeReady = "Ready"

	typeError = "Error"

	typeUpdating = "Updating"
)

// ApiGwReconciler reconciles a ApiGw object
type ApiGwReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func formatResourceName(resourceName string) string {
	return strings.Join([]string{"apigw", resourceName}, "-")
}

//+kubebuilder:rbac:groups=operator.scc-digitalhub.github.io,namespace=apigw-operator-system,resources=apigws,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.scc-digitalhub.github.io,namespace=apigw-operator-system,resources=apigws/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.io,namespace=apigw-operator-system,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,namespace=apigw-operator-system,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,namespace=apigw-operator-system,resources=services,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *ApiGwReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the ApiGw instance
	// The purpose is check if the Custom Resource for the Kind ApiGw
	// is applied on the cluster, if not we return nil to stop the reconciliation
	apigw := &operatorv1.ApiGw{}
	err := r.Get(ctx, req.NamespacedName, apigw)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the custom resource is not found then, it usually means that it was deleted or not created
			// In this way, we will stop the reconciliation
			log.Info("apigw resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get apigw")
		return ctrl.Result{}, err
	}

	// If status is unknown, set Deploying
	if apigw.Status.State == "" {
		log.Info("State unspecified, updating to initializing")
		apigw.Status.State = typeInitializing
		if err = r.Status().Update(ctx, apigw); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if apigw.Status.State == typeInitializing {
		log.Info("Initializing")

		// Get or create secret
		if apigw.Spec.Auth.Type != "" && apigw.Spec.Auth.Type != "none" {
			existingSecret := &corev1.Secret{}
			err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, existingSecret)
			if err != nil && apierrors.IsNotFound(err) {
				// Create secret
				secret, err := r.secretForApiGw(apigw, ctx)
				if err != nil {
					log.Error(err, "Failed to define new Secret resource for ApiGw")

					apigw.Status.State = typeError

					if err := r.Status().Update(ctx, apigw); err != nil {
						log.Error(err, genericStatusUpdateFailedMessage)
						return ctrl.Result{}, err
					}

					return ctrl.Result{}, err
				}
				log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				if err = r.Create(ctx, secret); err != nil {
					log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
					return ctrl.Result{}, err
				}
			} else if err != nil {
				log.Error(err, "Failed to check if secret already exists")
				return ctrl.Result{}, err
			} else {
				log.Error(err, "Secret already exists")

				apigw.Status.State = typeError

				if err := r.Status().Update(ctx, apigw); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}
		}

		// Get or create ingress
		existingIngress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, existingIngress)
		if err != nil && apierrors.IsNotFound(err) {
			//Create ingress
			ingress, err := r.ingressForApiGw(ctx, apigw)
			if err != nil {
				log.Error(err, "Failed to define new Ingress resource for ApiGw")

				apigw.Status.State = typeError

				if err := r.Status().Update(ctx, apigw); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}
			log.Info("Creating a new Ingress", "Ingress.Namespace", ingress.Namespace, "Ingress.Name", ingress.Name)
			if err = r.Create(ctx, ingress); err != nil {
				log.Error(err, "Failed to create new Ingress", "Ingress.Namespace", ingress.Namespace, "Ingress.Name", ingress.Name)
				return ctrl.Result{}, err
			}
		} else if err != nil {
			log.Error(err, "Failed to check if ingress already exists")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		} else {
			log.Error(err, "Ingress already exists")

			apigw.Status.State = typeError

			if err := r.Status().Update(ctx, apigw); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, err
		}

		apigw.Status.State = typeReady
		if err = r.Status().Update(ctx, apigw); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		log.Info("Ingress created successfully")
		return ctrl.Result{}, nil
	}

	if apigw.Status.State == typeReady {
		log.Info("Ready")

		return ctrl.Result{}, nil

		// TODO
		// Currently, we are unable to detect if the CR's password has been updated, as it is stored
		// as hash in the secret. Unfortunately, we cannot assume a reconcile trigger while in Ready
		// state corresponds to an update, as the reconcile-loop is then triggered infinitely.
		// This is due to it triggering not only when the CR's state is updated, but also when the
		// state of an associated resource is updated, which happens when the ingress gets an address.

		/*
			ingress := &networkingv1.Ingress{}
			err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, ingress)

			if err != nil && apierrors.IsNotFound(err) {
				log.Error(err, "Ingress not found")

				apigw.Status.State = typeError

				if err := r.Status().Update(ctx, apigw); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, err
			}

			apigw.Status.State = typeUpdating
			if err = r.Status().Update(ctx, apigw); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		*/
	}

	if apigw.Status.State == typeUpdating {
		log.Info("Updating")

		ingress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, ingress)
		if err != nil {
			log.Error(err, "Failed to get ingress")
			return ctrl.Result{}, err
		}

		// Update ingress
		rule := ingress.Spec.Rules[0]
		path := rule.HTTP.Paths[0]

		rule.Host = apigw.Spec.Host
		path.Path = apigw.Spec.Path
		path.Backend.Service.Name = apigw.Spec.Service
		path.Backend.Service.Port.Number = apigw.Spec.Port

		if err = r.Update(ctx, ingress); err != nil {
			log.Error(err, "Failed to update ingress")
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				log.Error(err, "Failed to clean up secret")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get secret")
			return ctrl.Result{}, err
		}

		// Recreate secret if auth is set
		if apigw.Spec.Auth.Type != "" && apigw.Spec.Auth.Type != "none" {
			secret, err := r.secretForApiGw(apigw, ctx)
			if err != nil {
				log.Error(err, "Failed to define new Secret resource for ApiGw")

				apigw.Status.State = typeError

				if err := r.Status().Update(ctx, apigw); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}
			log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
			if err = r.Create(ctx, secret); err != nil {
				log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				return ctrl.Result{}, err
			}
		}

		// Update status
		apigw.Status.State = typeReady
		if err := r.Status().Update(ctx, apigw); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}
	}

	if apigw.Status.State == typeError {
		// Delete ingress
		ingress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, ingress)
		if err == nil {
			if err := r.Delete(ctx, ingress); err != nil {
				log.Error(err, "Failed to clean up ingress")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get ingress")
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(apigw.Name), Namespace: apigw.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				log.Error(err, "Failed to clean up secret")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get secret")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// TODO Method currently unused, as there is no way to check if the password was updated (it's stored as hash in the secret)
/*
func crUpdated(ingress *networkingv1.Ingress, secret *corev1.Secret, cr *operatorv1.ApiGw) bool {
	rule := ingress.Spec.Rules[0]
	path := rule.IngressRuleValue.HTTP.Paths[0]
	service := path.Backend.Service
	if rule.Host != cr.Spec.Host || path.Path != cr.Spec.Path || service.Name != cr.Spec.Service || service.Port.Number != cr.Spec.Port {
		return true
	}

	if ingress.Annotations["nginx.ingress.kubernetes.io/auth-type"] != cr.Spec.Auth.Type {
		return true
	}
	authString := string(secret.Data["auth"])
	if strings.Split(authString, ":")[0] != cr.Spec.Auth.Basic.User {
		return true
	}

	return false
}
*/

func (r *ApiGwReconciler) ingressForApiGw(ctx context.Context, apigw *operatorv1.ApiGw) (*networkingv1.Ingress, error) {
	if apigw.Spec.Host == "" || apigw.Spec.Path == "" || apigw.Spec.Service == "" || apigw.Spec.Port == 0 {
		return nil, fmt.Errorf("host, path, service, port are required")
	}

	// check if services exist
	service := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: apigw.Spec.Service, Namespace: apigw.Namespace}, service)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("CR spec contains a non-existing service")
	}

	pathTypePrefix := networkingv1.PathTypePrefix
	nginx := "nginx"

	ingressSpec := networkingv1.IngressSpec{
		IngressClassName: &nginx,
		Rules: []networkingv1.IngressRule{{
			Host: apigw.Spec.Host,
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						PathType: &pathTypePrefix,
						Path:     apigw.Spec.Path,
						Backend: networkingv1.IngressBackend{
							Service: &networkingv1.IngressServiceBackend{
								Name: apigw.Spec.Service,
								Port: networkingv1.ServiceBackendPort{
									Number: int32(apigw.Spec.Port),
								},
							},
						},
					}},
				},
			},
		}},
	}

	// Add TLS to the spec, if enabled
	enableTls, found := os.LookupEnv(envEnableTls)
	if found && strings.EqualFold(enableTls, "true") {
		tls := networkingv1.IngressTLS{
			Hosts: []string{apigw.Spec.Host},
		}

		tlsSecretName, found := os.LookupEnv(envTlsSecretName)
		if found {
			tls.SecretName = tlsSecretName
		}

		ingressSpec.TLS = []networkingv1.IngressTLS{tls}
	}

	objectMeta := metav1.ObjectMeta{
		Name:      formatResourceName(apigw.Name),
		Namespace: apigw.Namespace,
		Labels:    labelsForApiGw(apigw.Name),
	}

	// Add auth annotations to metadata, if enabled
	if apigw.Spec.Auth.Type != "" && apigw.Spec.Auth.Type != "none" {
		objectMeta.Annotations = map[string]string{
			"nginx.ingress.kubernetes.io/auth-type":   apigw.Spec.Auth.Type,
			"nginx.ingress.kubernetes.io/auth-secret": formatResourceName(apigw.Name),
		}
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: objectMeta,
		Spec:       ingressSpec,
	}

	// Set the ownerRef for the Ingress
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
	if err := ctrl.SetControllerReference(apigw, ingress, r.Scheme); err != nil {
		return nil, err
	}
	return ingress, nil
}

func hashBcrypt(password string) (hash string, err error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(passwordBytes), nil
}

func (r *ApiGwReconciler) secretForApiGw(apigw *operatorv1.ApiGw, ctx context.Context) (*corev1.Secret, error) {
	// log := log.FromContext(ctx)

	name := apigw.Spec.Auth.Basic.User
	password := apigw.Spec.Auth.Basic.Password
	if name == "" || password == "" {
		return nil, fmt.Errorf("user and password are required")
	}

	hash, err := hashBcrypt(password)
	if err != nil {
		return nil, err
	}

	authString := name + ":" + hash

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(apigw.Name),
			Namespace: apigw.Namespace,
			Labels:    labelsForApiGw(apigw.Name),
		},
		StringData: map[string]string{"auth": authString},
	}

	if err := ctrl.SetControllerReference(apigw, secret, r.Scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

// labelsForApiGw returns the labels for selecting the resources
// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
func labelsForApiGw(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "ApiGw",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "apigw-operator",
		"app.kubernetes.io/part-of":    "apigw",
	}
}

// SetupWithManager sets up the controller with the Manager.
// Note that the Deployment will be also watched in order to ensure its
// desirable state on the cluster
func (r *ApiGwReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1.ApiGw{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}
