# Deploying CIMS to Kubernetes

These steps assume Docker Desktop with Kubernetes turned on (Settings > Kubernetes > Enable Kubernetes), and the image built with `docker build -t cims:1.0 .`.

## 1. Check the cluster

```bash
kubectl config use-context docker-desktop
kubectl get nodes
```

## 2. Create the namespace and the secrets

Secrets are created from the command line, so no secret value is stored in the repository.

```bash
kubectl create namespace cims --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic cims-secrets -n cims \
  --from-literal=secret-key="$(python -c 'import secrets;print(secrets.token_hex(24))')" \
  --from-literal=bootstrap-admin-password="$(python -c 'import secrets;print(secrets.token_urlsafe(16))')"
```

Keep the bootstrap admin password somewhere safe. It is needed for the first login (username `admin`).

## 3. Deploy

```bash
kubectl apply -f k8s/cims.yaml
kubectl rollout status deployment/cims -n cims
kubectl get pods -n cims
```

## 4. Check it works

```bash
kubectl port-forward -n cims svc/cims 8080:80
curl http://127.0.0.1:8080/health
```

Expected: `{"status":"ok"}`.

## Security controls in the manifest

| Control | Where |
|---|---|
| Non-root user (UID 10001) | `securityContext.runAsNonRoot`, `runAsUser` |
| Read-only root filesystem | `readOnlyRootFilesystem: true` (only `/app/data` and `/tmp` are writable) |
| No privilege escalation | `allowPrivilegeEscalation: false` |
| All Linux capabilities dropped | `capabilities.drop: [ALL]` |
| Seccomp profile | `seccompProfile: RuntimeDefault` |
| Pod Security "restricted" on the namespace | namespace labels |
| Secrets from Kubernetes Secret, not in YAML | `secretKeyRef` |
| Resource limits | `resources.limits` (CPU and memory) |
| Health checks | liveness and readiness on `/health` |
| No API token mounted | `automountServiceAccountToken: false` |
| Internal-only service | `type: ClusterIP` |
