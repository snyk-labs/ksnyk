import os
import subprocess

import click


@click.command()
@click.option("--show", is_flag=True, default=False)
def crd(show):
    """
    Setup the Vulnerability CRD in the cluster
    """
    package_dir, _ = os.path.split(__file__)
    crd_file = os.path.join(package_dir, "vulnerability.yaml")
    if show:
        with open(crd_file, "r") as handle:
            click.echo(handle.read())
    else:
        subprocess.run(["kubectl", "apply", "-f", crd_file])
