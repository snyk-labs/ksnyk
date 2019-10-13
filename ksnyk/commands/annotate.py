import click

from ksnyk.annotate import augment, augment_deployments, augment_replicationcontrollers
from ksnyk.helpers import get_snyk_projects, load_config


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
