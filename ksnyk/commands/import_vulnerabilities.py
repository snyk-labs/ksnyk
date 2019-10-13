import base64
import hashlib

import click
from kubernetes import client

from ksnyk.helpers import get_snyk_projects, load_config


@click.command()
@load_config
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

                body = {
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
                    api.get_namespaced_custom_object(
                        group, version, namespace, plural, ident
                    )
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
