import click

from ksnyk.commands import annotate, crd, import_vulnerabilities
from ksnyk.helpers import load_config


@click.group()
@load_config
def ksnyk():
    """
    ksnyk - an experimental tool for working with Snyk and Kubernetes
    """
    pass


ksnyk.add_command(annotate)
ksnyk.add_command(import_vulnerabilities, "import")
ksnyk.add_command(crd)

if __name__ == "__main__":
    ksnyk()
