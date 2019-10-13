# ksnyk

An experimental tool for working with Snyk and Kubernetes.


## Installation

```
pip install ksnyk
```

`ksnyk` is also available as a Docker image `garethr/ksnyk`.


## Configuration

In order to use `ksnyk` you need to have a Snyk account, and to export your Snyk API token
as `SNYK_TOKEN`. You also need to be using the new Snyk Kubernetes integration which is only
available to paying customers.

## Usage

`ksnyk` currently has three commands:

* `crd` - install or update the Vulnerability custom resource
* `import` - import vulnerability information from Snyk into the Kubernetes Vulnerability CRD
* `annotate` - annotate workloads with vulnerability information from Snyk


### crd

Init sets up or updates the Custom Resource definition for `Vulnerability` which is used by the `import` subcommand.
`init` requires a working version of `kubectl` to be on the path`

```console
$ ksnyk crd
customresourcedefinition.apiextensions.k8s.io/vulnerabilities.snyk.io unchanged
```

If you just want to grab the content of the CRD, maybe to integrate into some other tool, you can do so with:

```script
$ ksnyk crd --show
```


### Import

With the Vulnerability CRD installed in the cluster, you can import issues from Snyk into Kubernetes.

```console
$ ksnyk import
Skipping Snyk project snyk-kubernetes-demos:Pipfile
Skipping Snyk project garethr/snyky:latest
Checking snyk-linux-expat-450908
Updating c7b52f60593e16f12b8043a79d36bfe8 for default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Checking snyk-linux-musl-458116
Updating b4317dd19bc3846976b2e2d094f05b35 for default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Checking snyk-linux-git-175991
Updating 2091701137cc14d9c7450ed991b31d47 for default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Checking snyk-linux-expat-450908
Updating c7b52f60593e16f12b8043a79d36bfe8 for default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Checking snyk-linux-expat-450908
Updating c7b52f60593e16f12b8043a79d36bfe8 for default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Skipping Snyk project garethr/ubuntu:18.04
Checking snyk-linux-shadow-11609
...
```

With vulnerabilites imported you can then use the Kubernetes API to check for vulnerabilities in a specific namespoace.

```console
$ kubectl get vulns
NAME                               TITLE                                  IMAGE                             PACKAGE                         SEVERITY
02fdaaaf731bb70448ea3b92375a1936   Insufficient Entropy                   nginx                             gcc-8/libstdc++6                high
033b95cadde71cb4feb074a765bdae79   Use After Free                         nginx                             tiff/libtiff5                   high
050c8d79b573160e0189023da896bc44   Credentials Management                 nginx                             systemd/libsystemd0             high
0562337227793e853b1611e3f050880c   Out-of-Bounds                          nginx                             pcre3/libpcre3                  high
062fba0e3e04fe6fabfef22c701948c2   Improper Input Validation              nginx                             coreutils                       medium
069b28f8941f58ae1244dd968a484f8e   Divide By Zero                         nginx                             libjpeg-turbo/libjpeg62-turbo   medium
0db756987886a7dc97879c6c4b5c0b1d   Out-of-Bounds                          nginx                             libpng1.6/libpng16-16           high
0f7cc50ad19f757af7ac7aab96e8c23d   Cryptographic Issues                   nginx                             libgcrypt20                     high
...
```

You can access more information if you have a wide terminal, using the standard `wide` output.

```console
$ kubectl get vulns -o wide
```


### Annotate

Annotate adds annotates to workloads with a matching Snyk project. Specifically it adds addnotations for:

* The number of high, medium and low severity vulnerabilities
* A link to the Snyk project for the workload

```console
$ ksnyk annotate
Found snyky in Kubernetes
Found compose in Kubernetes
Found compose-api in Kubernetes
Found coredns in Kubernetes
Found tiller-deploy in Kubernetes
Found snyk-monitor in Kubernetes
Annotating default/deployment.apps/snyky:docker.io/garethr/garethr_snyky
Found example-rc in Kubernetes
Annotating default/replicationcontroller/example-rc:nginx
```

```console
$ kubectl describe rc example-rc
Name:         example-rc
Namespace:    default
Selector:     app=nginx
Labels:       
Annotations:  snyk.io/high-priority-vulnerabilities: 25
              snyk.io/low-priority-vulnerabilities: 7
              snyk.io/medium-priority-vulnerabilities: 36
              snyk.io/url: https://app.dev.snyk.io/org/aaa/project/bbb
Replicas:     2 current / 2 desired
...
```


## Running in Kubernetes

`ksnyk` can be run one-off as above, but you can also run it regularly keep new workloads and projects
up-to-date as new vulnerabilies are announced or fixed. For this we can use Kubernetes `CronJob`.

You'll first need to create a Kubernetes `Secret` containing your `SNYK_TOKEN` for API access.

```
kubectl create secret generic snyk --from-literal=token=<YOUR_SNYK_TOKEN>
```

You can then create two CronJobs that will periodically run `annotate` and `import` shown above.

```
kubectl apply -f ksnyk.yaml
```
