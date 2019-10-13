import os
import sys

import click
import snyk
from kubernetes import config


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

    return click.option(
        "--cluster",
        is_flag=True,
        default=False,
        expose_value=False,
        help="Load Kubernetes credentials from cluster",
        callback=callback,
    )(f)
