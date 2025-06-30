# API Gateway Operator


![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/tn-aixpa/apigw-operator/release.yaml?event=release) [![license](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/tn-aixpa/apigw-operator/LICENSE) ![GitHub Release](https://img.shields.io/github/v/release/tn-aixpa/apigw-operator)
![Status](https://img.shields.io/badge/status-stable-gold)


A Kubernetes operator to launch ingresses (Nginx) for services.

Explore the full documentation at the [link](https://scc-digitalhub.github.io/docs/).

## Quick start

There is an available deployment file ready to be used. You can use it to install the operator and the CRD in your Kubernetes environment:

```sh
kubectl apply -f deployment.yaml
```

An example custom resource is found at `config/samples/operator_v1_dremiorestserver.yaml`. The CRD included in the deployment file is found at `config/crd/bases/operator.dremiorestserver.com_dremiorestservers.yaml`.

To launch a CR:

```sh
kubectl apply -f config/samples/operator_v1_apigw.yaml
```

## Configuration

You can start from the provided "deployment.yaml" file and tailor it to your needs, e.g. modifying the resources that will be provided to CR containers.

A number of environment variables must be configured. If you're using the `deployment.yaml` file, you will find them towards the end of the file.
```
WATCH_NAMESPACE: apigw-operator-system
ENABLE_TLS: true
TLS_SECRET_NAME: ingresssecret
INGRESS_CLASS_NAME: nginx
```

### Custom Resource Properties

The custom resource's properties are:

- `host`: **Required**. URL to host the access point on.
- `path`: **Required**. Path within the host to host the access point on.
- `service`: **Required**. Name of the Kubernetes service.
- `port`: **Required**. Internal port the service is listening on.
- `auth`: *Optional*. A structure to configure authentication. If left empty, authentication is disabled. Must be disabled if `INGRESS_CLASS_NAME` is not `nginx`, or resources will result in error. Has the following properties:
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
```

Another valid sample (requires `nginx` as `INGRESS_CLASS_NAME`):
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

## Development

The operator is developed with [Operator-SDK](https://sdk.operatorframework.io). Refer to its documentation and [tutorial](https://sdk.operatorframework.io/docs/building-operators/golang/tutorial/) for development details and commands. The [project layout](https://sdk.operatorframework.io/docs/overview/project-layout/) is also described there.

See CONTRIBUTING for contribution instructions.

## Security Policy

The current release is the supported version. Security fixes are released together with all other fixes in each new release.

If you discover a security vulnerability in this project, please do not open a public issue.

Instead, report it privately by emailing us at digitalhub@fbk.eu. Include as much detail as possible to help us understand and address the issue quickly and responsibly.

## Contributing

To report a bug or request a feature, please first check the existing issues to avoid duplicates. If none exist, open a new issue with a clear title and a detailed description, including any steps to reproduce if it's a bug.

To contribute code, start by forking the repository. Clone your fork locally and create a new branch for your changes. Make sure your commits follow the [Conventional Commits v1.0](https://www.conventionalcommits.org/en/v1.0.0/) specification to keep history readable and consistent.

Once your changes are ready, push your branch to your fork and open a pull request against the main branch. Be sure to include a summary of what you changed and why. If your pull request addresses an issue, mention it in the description (e.g., “Closes #123”).

Please note that new contributors may be asked to sign a Contributor License Agreement (CLA) before their pull requests can be merged. This helps us ensure compliance with open source licensing standards.

We appreciate contributions and help in improving the project!

## Authors

This project is developed and maintained by **DSLab – Fondazione Bruno Kessler**, with contributions from the open source community. A complete list of contributors is available in the project’s commit history and pull requests.

For questions or inquiries, please contact: [digitalhub@fbk.eu](mailto:digitalhub@fbk.eu)

## Copyright and license

Copyright © 2025 DSLab – Fondazione Bruno Kessler and individual contributors.

This project is licensed under the Apache License, Version 2.0.
You may not use this file except in compliance with the License. Ownership of contributions remains with the original authors and is governed by the terms of the Apache 2.0 License, including the requirement to grant a license to the project.
