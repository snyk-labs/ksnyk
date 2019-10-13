import click

from ksnyk.commands import annotate, crd, import_vulnerabilities
from ksnyk.helpers import load_config


@click.group()
@load_config
def cli():
    """
    An experimental set of tools for working with Snyk and Kubernetes
    """
    pass


cli.add_command(annotate)
cli.add_command(import_vulnerabilities, "import")
cli.add_command(crd)

if __name__ == "__main__":
    cli()
