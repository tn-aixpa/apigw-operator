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
	"strings"
	"time"

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

// Definitions to manage status conditions
const (
	// Launch deployment and service
	typeDeploying = "Deploying"

	typeRunning = "Running" //TODO cambiare in ready perché non ci sono operazioni da controllare

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

//+kubebuilder:rbac:groups=operator.digitalhub.it,resources=apigws,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.digitalhub.it,resources=apigws/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking,namespace=dremions,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,namespace=dremions,resources=secrets,verbs=get;list;watch;create;update;patch;delete

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
		log.Info("State unspecified, updating to deploying")
		apigw.Status.State = typeDeploying
		if err = r.Status().Update(ctx, apigw); err != nil {
			log.Error(err, "failed to update ApiGw status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if apigw.Status.State == typeDeploying {
		log.Info("Deploying")

		// Get or create secret
		//TODO

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
					log.Error(err, "failed to update ApiGw status")
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
			log.Error(err, "Failed to get ingress")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		apigw.Status.State = typeRunning
		if err = r.Status().Update(ctx, apigw); err != nil {
			log.Error(err, "failed to update ApiGw status")
			return ctrl.Result{}, err
		}

		log.Info("Ingress created successfully")
		// Ingress created successfully
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if apigw.Status.State == typeRunning {
		//TODO controllare solo se bisogna passare in updating
	}

	if apigw.Status.State == typeUpdating {
		//TODO
	}

	if apigw.Status.State == typeError {
		//TODO
	}

	return ctrl.Result{}, nil
}

func crUpdated(dep *networkingv1.Ingress, cr *operatorv1.ApiGw) bool {
	return false
}

// deploymentForDremiorestserver returns a DremioRestServer Deployment object
//TODO usare per ingress stesso namespace della CR, cercare servizi nel namespace della CR
//TODO quando la Cr viene modificata non serve cancellare l'ingress ma solo aggiornarlo
func (r *ApiGwReconciler) ingressForApiGw(ctx context.Context, apigw *operatorv1.ApiGw) (*networkingv1.Ingress, error) {
	// check if services exist
	service := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: apigw.Spec.Hosts[0].Paths[0].Service, Namespace: apigw.Namespace}, service)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("CR spec contains a non-existing service")
	}

	pathTypePrefix := networkingv1.PathTypePrefix

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(apigw.Name),
			Namespace: apigw.Namespace,
			Labels:    labelsForApiGw(apigw.Name),
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: apigw.Spec.Hosts[0].Host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							PathType: &pathTypePrefix,
							Path: apigw.Spec.Hosts[0].Paths[0].Path,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: apigw.Spec.Hosts[0].Paths[0].Service,
									Port: networkingv1.ServiceBackendPort{
										Number: int32(apigw.Spec.Hosts[0].Paths[0].Port),
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	// Set the ownerRef for the Ingress
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
	if err := ctrl.SetControllerReference(apigw, ingress, r.Scheme); err != nil {
		return nil, err
	}
	return ingress, nil
}

//TODO mettere nel secret le credenziali, già encoded con libreria come le vuole nginx
func (r *ApiGwReconciler) secretForApiGw(apigw *operatorv1.ApiGw) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(apigw.Name),
			Namespace: apigw.Namespace,
			//Labels:    labelsForApiGw(apigw.Name, tag), //TODO
		},
		StringData: map[string]string{"": ""}, //TODO
	}

	if err := ctrl.SetControllerReference(apigw, secret, r.Scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

// labelsForApiGw returns the labels for selecting the resources
// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
func labelsForApiGw(name string/*, version string*/) map[string]string {
	selectors := selectorsForApiGw(name)
	//selectors["app.kubernetes.io/version"] = version
	selectors["app.kubernetes.io/part-of"] = "apigw"
	return selectors
}

func selectorsForApiGw(name string) map[string]string {
	return map[string]string{"app.kubernetes.io/name": "ApiGw",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "apigw-operator",
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
