# API Gateway Operator

A Kubernetes operator to launch ingresses for services.

## Installation
A number of environment variables must be configured. If you're using the `deployment.yaml` file, you will find them towards the end of the file.
```
WATCH_NAMESPACE: apigw-operator-system
ENABLE_TLS: true
TLS_SECRET_NAME: ingresssecret
INGRESS_CLASS_NAME: nginx
```

Install operator and CRD:
```sh
kubectl apply -f deployment.yaml
```

An example CR is found at `config/samples/operator_v1_apigw.yaml`. Apply it with:
```sh
kubectl apply -f config/samples/operator_v1_apigw.yaml
```

## API Gateway custom resource
The custom resource's properties are:

- `host`: **Required**. URL to host the access point on.
- `path`: **Required**. Path within the host to host the access point on.
- `service`: **Required**. Name of the Kubernetes service.
- `port`: **Required**. Internal port the service is listening on.
- `auth`: *Optional*. A structure to configure authentication. If left empty, authentication is disabled. Has the following properties:
  - `type`: `basic` or `none` (disabled).
  - `basic`: Structure for basic authentication. Has the following properties:
    - `user`
    - `password`

A valid sample spec configuration is:
``` yaml
...
spec:
  host: foo.bar.com
  path: /
  service: myservice
  port: 9080
  auth:
    type: basic
    basic:
      user: user
      password: password
```

Another valid sample:
``` yaml
...
spec:
  host: foo.bar.com
  path: /
  service: myservice
  port: 9080
```

## Updating the CR
At the moment, updating the CR is not supported (no change will happen) due to difficulties with detecting a password change. If you wish to update the CR, either delete and recreate it, or manually change its state to `Updating`.
