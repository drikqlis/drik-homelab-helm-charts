## Usage

[Helm](https://helm.sh) must be installed to use the charts.  Please refer to
Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:

  helm repo add drik-homelab https://drikqlis.github.io/drik-homelab-helm-charts

If you had already added this repo earlier, run `helm repo update` to retrieve
the latest versions of the packages.  You can then run `helm search repo
drik-homelab` to see the charts.

To install the jellyfin chart:

    helm install my-jellyfin drik-homelab/jellyfin

To uninstall the chart:

    helm delete my-jellyfin
