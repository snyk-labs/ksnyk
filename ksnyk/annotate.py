import click
from kubernetes import client


def add_to_replicationcontrollers(projects):
    api = client.CoreV1Api()
    add_to(
        projects,
        "replicationcontroller",
        api.list_replication_controller_for_all_namespaces,
        api.patch_namespaced_replication_controller,
    )


def add_to_deployments(projects):
    api = client.AppsV1Api()
    add_to(
        projects,
        "deployment.apps",
        api.list_deployment_for_all_namespaces,
        api.patch_namespaced_deployment,
    )


def add_to_cronjobs(projects):
    api = client.BatchV1beta1Api()
    add_to(
        projects,
        "cronjob.batc",
        api.list_cron_job_for_all_namespaces,
        api.patch_namespaced_cron_job,
    )


def add_to(projects, kind, list_function, patch_function):
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
                obj.metadata.annotations[
                    "snyk.io/medium-priority-vulnerabilities"
                ] = str(project.issueCountsBySeverity.medium)
                obj.metadata.annotations["snyk.io/low-priority-vulnerabilities"] = str(
                    project.issueCountsBySeverity.low
                )
                obj.metadata.annotations["snyk.io/url"] = str(project.browseUrl)
                patch_function(obj.metadata.name, obj.metadata.namespace, obj)
        except ValueError:
            pass
