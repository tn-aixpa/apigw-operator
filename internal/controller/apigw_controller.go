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

	"crypto/sha256"
	"encoding/hex"

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

const envIngressClassName = "INGRESS_CLASS_NAME"
const envEnableTls = "ENABLE_TLS"
const envTlsSecretName = "TLS_SECRET_NAME"

const genericStatusUpdateFailedMessage = "failed to update ApiGw status"
const ingressClassMissingMessage = "ingress class name environment variable is not specified"

const secretHashAnnotation = "nginx.ingress.kubernetes.io/hash"

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
	cr := &operatorv1.ApiGw{}
	err := r.Get(ctx, req.NamespacedName, cr)
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
	if cr.Status.State == "" {
		log.Info("State unspecified, updating to initializing")
		cr.Status.State = typeInitializing
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if cr.Status.State == typeInitializing {
		log.Info("Initializing")

		if cr.Spec.Auth.Type != "" && cr.Spec.Auth.Type != "none" {

			// Check nginx is set
			ingressClassName, found := os.LookupEnv(envIngressClassName)
			if !found {
				log.Error(err, ingressClassMissingMessage)
				return setErrorState(r, ctx, cr, err)
			}
			if ingressClassName != "nginx" {
				log.Error(err, "Invalid configuration: auth is only supported with nginx ingress class name")
				return setErrorState(r, ctx, cr, err)
			}

			// Secret
			existingSecret := &corev1.Secret{}
			err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, existingSecret)
			if err != nil && apierrors.IsNotFound(err) {
				// Create secret
				secret, err := r.secretForApiGw(cr)
				if err != nil {
					log.Error(err, "Failed to define new Secret resource for ApiGw")
					return setErrorState(r, ctx, cr, err)
				}
				log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				if err = r.Create(ctx, secret); err != nil {
					log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
					return ctrl.Result{}, err
				}

				// Write username:password hash in CR state
				cr.Status.Hash = hashed(cr.Spec.Auth.Basic.User + ":" + cr.Spec.Auth.Basic.Password)

			} else if err != nil {
				log.Error(err, "Failed to check if secret already exists")
				return ctrl.Result{}, err
			}
		}

		// Get or create ingress
		existingIngress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, existingIngress)
		if err != nil && apierrors.IsNotFound(err) {
			//Create ingress
			ingress, err := r.ingressForApiGw(ctx, cr)
			if err != nil {
				log.Error(err, "Failed to define new Ingress resource for ApiGw")
				return setErrorState(r, ctx, cr, err)
			}
			log.Info("Creating a new Ingress", "Ingress.Namespace", ingress.Namespace, "Ingress.Name", ingress.Name)
			if err = r.Create(ctx, ingress); err != nil {
				log.Error(err, "Failed to create new Ingress", "Ingress.Namespace", ingress.Namespace, "Ingress.Name", ingress.Name)
				return ctrl.Result{}, err
			}
			log.Info("Ingress created successfully")
		} else if err != nil {
			log.Error(err, "Failed to check if ingress already exists")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		} else {
			log.Info("Ingress already exists")
		}

		cr.Status.State = typeReady
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	if cr.Status.State == typeReady {
		log.Info("Ready")

		// Check secret only if auth is set
		if cr.Spec.Auth.Type != "" && cr.Spec.Auth.Type != "none" {
			// Get ingress class name
			ingressClassName, found := os.LookupEnv(envIngressClassName)
			if !found {
				log.Error(err, ingressClassMissingMessage)
				return setErrorState(r, ctx, cr, err)
			}

			// Check nginx is set
			if ingressClassName != "nginx" {
				log.Error(err, "Invalid configuration: auth is only supported with nginx ingress class name")
				return setErrorState(r, ctx, cr, err)
			}

			secret := &corev1.Secret{}
			err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
			if err != nil {
				return handleMissingResource(r, ctx, cr, err)
			}
		}

		// Check ingress
		ingress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, ingress)
		if err != nil {
			return handleMissingResource(r, ctx, cr, err)
		}

		// Check if CR was updated
		updated, err := crUpdated(r, ctx, cr)
		if err != nil {
			log.Error(err, "Failed to check if the CR has been updated")
			return setErrorState(r, ctx, cr, err)
		}
		if updated {
			cr.Status.State = typeUpdating
			if err = r.Status().Update(ctx, cr); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil

	}

	if cr.Status.State == typeUpdating {
		log.Info("Updating")

		ingress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, ingress)
		if err != nil {
			log.Error(err, "Failed to get ingress")
			return ctrl.Result{}, err
		}

		// Update ingress
		ingress.Spec.Rules[0].Host = cr.Spec.Host

		rule := ingress.Spec.Rules[0]
		rule.HTTP.Paths[0].Path = cr.Spec.Path

		path := rule.HTTP.Paths[0]

		path.Backend.Service.Name = cr.Spec.Service
		path.Backend.Service.Port.Number = cr.Spec.Port

		ingress.Spec.Rules[0].Host = cr.Spec.Host

		ingress.ObjectMeta.Annotations = map[string]string{
			"nginx.ingress.kubernetes.io/auth-type":   cr.Spec.Auth.Type,
			"nginx.ingress.kubernetes.io/auth-secret": formatResourceName(cr.Name),
		}

		if err = r.Update(ctx, ingress); err != nil {
			log.Error(err, "Failed to update ingress")
			return ctrl.Result{}, err
		}

		// Get ingress class name
		ingressClassName, found := os.LookupEnv(envIngressClassName)
		if !found {
			log.Error(err, ingressClassMissingMessage)
			return setErrorState(r, ctx, cr, err)
		}

		if ingressClassName == "nginx" {
			// Delete secret
			secret := &corev1.Secret{}
			err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
			if err == nil {
				if err := r.Delete(ctx, secret); err != nil {
					log.Error(err, "Failed to clean up secret")
				}
			} else if !apierrors.IsNotFound(err) {
				log.Error(err, "Failed to get secret")
				return ctrl.Result{}, err
			}

			cr.Status.Hash = ""
		}

		// Recreate secret if auth is set
		if cr.Spec.Auth.Type != "" && cr.Spec.Auth.Type != "none" {
			// No need to check if nginx is set, as it is already done in running state

			// Create secret
			secret, err := r.secretForApiGw(cr)
			if err != nil {
				log.Error(err, "Failed to define new Secret resource for ApiGw")
				return setErrorState(r, ctx, cr, err)
			}
			log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
			if err = r.Create(ctx, secret); err != nil {
				log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				return ctrl.Result{}, err
			}

			// Write username:password hash in CR state
			cr.Status.Hash = hashed(cr.Spec.Auth.Basic.User + ":" + cr.Spec.Auth.Basic.Password)
		}

		// Update status
		cr.Status.State = typeReady
		if err := r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}
	}

	if cr.Status.State == typeError {
		// Delete ingress
		ingress := &networkingv1.Ingress{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, ingress)
		if err == nil {
			if err := r.Delete(ctx, ingress); err != nil {
				log.Error(err, "Failed to clean up ingress")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get ingress")
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				log.Error(err, "Failed to clean up secret")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get secret")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func handleMissingResource(r *ApiGwReconciler, ctx context.Context, cr *operatorv1.ApiGw, err error) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if apierrors.IsNotFound(err) {
		cr.Status.State = typeInitializing
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	log.Error(err, "error while retrieving resource")
	return ctrl.Result{}, err
}

/*
Normally, we are unable to detect if the CR's password has been updated, as it is
stored as hash in the secret.

We also cannot assume a reconcile trigger while in Ready state corresponds
to an update, as the reconcile-loop is then triggered infinitely. This is due to it
triggering not only when the CR's state is updated, but also when the state of an
associated resource is updated, which happens when the ingress gets an address.

To circumvent these issues, we store the password hashed in the CR's state.
*/
func crUpdated(r *ApiGwReconciler, ctx context.Context, cr *operatorv1.ApiGw) (bool, error) {
	log := log.FromContext(ctx)

	// Get ingress
	ingress := &networkingv1.Ingress{}
	err := r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, ingress)

	if err != nil && apierrors.IsNotFound(err) {
		return false, err
	}

	rule := ingress.Spec.Rules[0]
	path := rule.IngressRuleValue.HTTP.Paths[0]
	service := path.Backend.Service
	if rule.Host != cr.Spec.Host || path.Path != cr.Spec.Path || service.Name != cr.Spec.Service || service.Port.Number != cr.Spec.Port {
		return true, nil
	}

	if !equivalentAuth(ingress.Annotations["nginx.ingress.kubernetes.io/auth-type"], cr.Spec.Auth.Type) {
		return true, nil
	}

	if cr.Spec.Auth.Type != "" && cr.Spec.Auth.Type != "none" {
		// To check if the password has changed, we use a hashed string we stored in the CR's state
		if cr.Status.Hash != hashed(cr.Spec.Auth.Basic.User+":"+cr.Spec.Auth.Basic.Password) {
			log.Info("Found hash mismatch; status: " + cr.Status.Hash + ", val: " + hashed(cr.Spec.Auth.Basic.User+":"+cr.Spec.Auth.Basic.Password))
			return true, nil
		}
	}

	return false, nil
}

/*
Checks if the two auths specified are equivalent.
*/
func equivalentAuth(auth1 string, auth2 string) bool {
	if auth1 == "" || auth1 == "none" {
		return auth2 == "" || auth2 == "none"
	}

	return auth1 == auth2
}

func (r *ApiGwReconciler) ingressForApiGw(ctx context.Context, apigw *operatorv1.ApiGw) (*networkingv1.Ingress, error) {
	if apigw.Spec.Host == "" || apigw.Spec.Path == "" || apigw.Spec.Service == "" || apigw.Spec.Port == 0 {
		return nil, fmt.Errorf("host, path, service, port are required")
	}

	// Check if services exist
	service := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: apigw.Spec.Service, Namespace: apigw.Namespace}, service)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("CR spec contains a non-existing service")
	}

	pathTypePrefix := networkingv1.PathTypePrefix
	ingressClassName, found := os.LookupEnv(envIngressClassName)
	if !found {
		return nil, fmt.Errorf(ingressClassMissingMessage)
	}

	ingressSpec := networkingv1.IngressSpec{
		IngressClassName: &ingressClassName,
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
	if apigw.Spec.Auth.Type != "" && apigw.Spec.Auth.Type != "none" && ingressClassName == "nginx" {
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

func (r *ApiGwReconciler) secretForApiGw(apigw *operatorv1.ApiGw) (*corev1.Secret, error) {
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

	// Write username:password SHA hash in annotation
	annotations := map[string]string{
		secretHashAnnotation: hashed(apigw.Spec.Auth.Basic.User + ":" + apigw.Spec.Auth.Basic.Password),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        formatResourceName(apigw.Name),
			Namespace:   apigw.Namespace,
			Labels:      labelsForApiGw(apigw.Name),
			Annotations: annotations,
		},
		StringData: map[string]string{"auth": authString},
	}

	if err := ctrl.SetControllerReference(apigw, secret, r.Scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

func setErrorState(r *ApiGwReconciler, ctx context.Context, cr *operatorv1.ApiGw, err error) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	cr.Status.State = typeError

	if err := r.Status().Update(ctx, cr); err != nil {
		log.Error(err, genericStatusUpdateFailedMessage)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, err
}

func hashed(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
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
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}
