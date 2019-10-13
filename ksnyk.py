import os
import sys
import subprocess
import base64
import hashlib

import click
from kubernetes import client, config
import snyk


def get_snyk_projects():
    """
    Return a list of all Snyk projects, or if a SNYK_ORG
    is specified all Snyk projects in that organization
    """
    try:
        token = os.environ["SNYK_TOKEN"]
    except KeyError:
        sys.exit("You must provide a SNYK_TOKEN to run Snyk Shell")

    api = os.environ.get("SNYK_API")
    if api:
        snyk_client = snyk.SnykClient(token, api)
    else:
        snyk_client = snyk.SnykClient(token)

    org_id = os.environ.get("SNYK_ORG")
    if org_id:
        org = snyk_client.organizations.get(org_id)
        return org.projects.all()
    else:
        return snyk_client.projects.all()



def load_config(f):
    def callback(ctx, param, value):
        if value:
            config.load_incluster_config()
        else:
            config.load_kube_config()
    return click.option('--cluster',
                        is_flag=True,
                        default=False,
                        expose_value=False,
                        help='Load Kubernetes credentials from cluster',
                        callback=callback)(f)


@click.group()
@load_config
def ksnyk():
    """
    ksnyk - an experimental tool for working with Snyk and Kubernetes
    """
    pass


@click.group(invoke_without_command=True)
@load_config
@click.pass_context
def annotate(ctx):
    """
    Add vulnerability annotations to all Kubernetes resources
    """

    ctx.ensure_object(dict)

    ctx.obj["projects"] = get_snyk_projects()

    if ctx.invoked_subcommand is None:
        augment_deployments(ctx.obj["projects"])
        augment_replicationcontrollers(ctx.obj["projects"])


@click.command()
@load_config
@click.pass_context
def annotate_deployments(ctx):
    """
    Add vulnerability annotations to deployments
    """
    augment_deployments(ctx.obj["projects"])


@click.command()
@load_config
@click.pass_context
def annotate_replicationcontrollers(ctx):
    """
    Add vulnerability annotations to replication controllers
    """
    augment_replicationcontrollers(ctx.obj["projects"])


annotate.add_command(annotate_deployments, "deployments")
annotate.add_command(annotate_replicationcontrollers, "replicationcontrollers")


def augment_replicationcontrollers(projects):
    api = client.CoreV1Api()
    augment(
        projects,
        "replicationcontroller",
        api.list_replication_controller_for_all_namespaces,
        api.patch_namespaced_replication_controller,
    )


def augment_deployments(projects):
    api = client.AppsV1Api()
    augment(
        projects,
        "deployment.apps",
        api.list_deployment_for_all_namespaces,
        api.patch_namespaced_deployment,
    )


def augment(projects, kind, list_function, patch_function):
    """
    Given a list of projects and the required functions for a given kind
    Add annotations to the object with information from the Snyk API
    """
    response = list_function(watch=False)
    objects = {}
    for obj in response.items:
        click.echo("Found %s in Kubernetes" % obj.metadata.name)
        objects["%s/%s/%s" % (obj.metadata.namespace, kind, obj.metadata.name)] = obj

    for project in projects:
        try:
            name, image = project.name.split(":")
            if name in objects.keys():
                click.echo("Annotating %s" % project.name)
                obj = objects[name]
                obj.metadata.annotations["snyk.io/high-priority-vulnerabilities"] = str(
                    project.issueCountsBySeverity.high
                )
                obj.metadata.annotations["snyk.io/medium-priority-vulnerabilities"] = str(
                    project.issueCountsBySeverity.medium
                )
                obj.metadata.annotations["snyk.io/low-priority-vulnerabilities"] = str(
                    project.issueCountsBySeverity.low
                )
                obj.metadata.annotations["snyk.io/url"] = str(project.browseUrl)
                patch_function(obj.metadata.name, obj.metadata.namespace, obj)
        except ValueError:
            pass



@click.command()
def import_vulnerabilities():
    """
    Import Vulnerabilities from Snyk into the CRD
    """
    api = client.CustomObjectsApi()
    for project in get_snyk_projects():
        try:
            name, image = project.name.split(":")
            namespace, kind, resource = name.split("/")
            for vuln in project.vulnerabilities:
                click.echo("Checking %s" % vuln.id.lower())
                group = "snyk.io"
                version = "v1"
                plural = "vulnerabilities"
                path = "%s/%s:%s" % (kind, resource, image)
                combined = "%s-%s" % (path.replace("/", "-"), vuln.id.lower())
                encoded = combined.encode("utf-8")
                ident = hashlib.md5(encoded).hexdigest()

                body={
                    "apiVersion": "snyk.io/v1",
                    "kind": "Vulnerability",
                    "metadata": {"name": ident},
                    "spec": {
                        "title": vuln.title,
                        "id": vuln.id.lower(),
                        "path": path,
                        "kind": kind,
                        "resource": resource,
                        "image": image,
                        "url": vuln.url,
                        "description": vuln.description,
                        "package": vuln.package,
                        "version": vuln.version,
                        "severity": vuln.severity,
                        "isUpgradable": vuln.isUpgradable,
                        "language": vuln.language,
                        "packageManager": vuln.packageManager,
                        "publicationTime": vuln.publicationTime,
                        "disclosureTime": vuln.disclosureTime,
                        "cvssV3": vuln.CVSSv3,
                        "cvssScore": vuln.cvssScore,
                    },
                }
                try:
                    api.get_namespaced_custom_object(group, version, namespace, plural, ident)
                    api.patch_namespaced_custom_object(
                        group=group,
                        version=version,
                        namespace=namespace,
                        plural=plural,
                        name=ident,
                        body=body,
                    )
                    click.echo("Updating %s for %s" % (ident, project.name))
                except client.rest.ApiException:
                    try:
                        api.create_namespaced_custom_object(
                            group=group,
                            version=version,
                            namespace=namespace,
                            plural=plural,
                            body=body,
                        )
                        click.echo("Creating %s for %s" % (ident, project.name))
                    except client.rest.ApiException as e:
                        click.echo("Error with %s: %s" % (project.name, e))
        except ValueError as e:
            click.echo("Skipping Snyk project %s" % (project.name))
            # Not a Kubernetes project
            pass


@click.command()
@click.option("--show", is_flag=True, default=False)
def crd(show):
    """
    Setup the Vulnerability CRD in the cluster
    """
    package_dir, _ = os.path.split(__file__)
    crd_file = os.path.join(package_dir, "vulnerability.yaml")
    if show:
        with open(crd_file, 'r') as handle:
            click.echo(handle.read())
    else:
        subprocess.run(["kubectl", "apply", "-f", crd_file])


ksnyk.add_command(annotate)
ksnyk.add_command(import_vulnerabilities, "import")
ksnyk.add_command(crd)

if __name__ == "__main__":
    ksnyk()
