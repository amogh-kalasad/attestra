# Attestra deploy (Phase 6.5)

- `../Dockerfile` – one image; default CMD runs the API, `attestra worker` runs the worker.
- `helm/attestra/` – chart: API Deployment (+ `attestra init` migration init container), worker Deployment (1 replica, InstanceLock), Service, PVC, Secret, app NetworkPolicy, optional example scanner Job + NetworkPolicy.
- `k8s/` – raw templates: per-scan Job, its NetworkPolicy (egress only to pinned IP /32), namespace default-deny.

Commands (VERIFY):

    docker build -t attestra:dev .
    helm lint deploy/helm/attestra --set secrets.apiKeyPepper=x --set secrets.sessionSecret=y
    helm template attestra deploy/helm/attestra --set secrets.apiKeyPepper=x --set secrets.sessionSecret=y
    helm install attestra deploy/helm/attestra --set secrets.apiKeyPepper=... --set secrets.sessionSecret=...

NetworkPolicy needs a CNI that enforces it (Calico/Cilium; kind's default kindnet does NOT).
The per-runner egress IP is enforced by an egress gateway, not by NetworkPolicy.
Not done yet: worker creating Jobs via the Kubernetes API, Go on-prem runner (outbound mTLS).

Step 6.4 (OIDC + Vault/OpenBao secrets): see `../docs/IDENTITY_AND_SECRETS.md`, values `oidc.*` and `secretsStore.*`,
example realm `keycloak/attestra-realm.example.json`.

Temporal (Phase 6.2, optional): set ATTESTRA_ORCHESTRATOR=temporal and ATTESTRA_TEMPORAL_ADDRESS on API and worker; the worker Deployment then runs a Temporal worker. See ../docs/TEMPORAL.md.
