# Netlens plugin: Kubernetes

A `hypervisor` plugin.

Shows a **Kubernetes cluster** (k3s, kubeadm, RKE2, Talos, microk8s ...) as hosts and guests: the nodes as hosts with their address and Ready state, the pods as guests of the node they run on, with namespace, workload, image, host ports, restarts and readiness. Completed pods (finished jobs) are left out.

> **Status: tested against the real software in a lab** (k3s v1.36.5 (one node, Deployments, DaemonSets, Jobs). Multi-node clusters, host-network pods and LAN-routable pod addresses are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Apply the read-only account from the box at the top of the plugin's page (a service account that can only list nodes and pods), then `kubectl -n kube-system create token netlens --duration=87600h`.
2. In Netlens install **Kubernetes**, add a line with the API server address (`https://192.168.0.10:6443`) and the token. Optionally list the namespaces to read.
3. Test, enable.

## Good to know

- Pod addresses lie inside the cluster network and are not reported unless you switch *Report pod addresses* on (for pods with LAN-routable addresses). Host-network pods never get one: their address is the node's.
- A pod's *project* is its namespace and its *service* the workload that owns it (a ReplicaSet's hash is removed).
- The token needs `get`/`list` on nodes and pods; Netlens treats 'forbidden' like a refused login and stops retrying until you act.
