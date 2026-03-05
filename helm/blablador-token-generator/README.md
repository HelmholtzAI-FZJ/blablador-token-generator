# Helm Chart: blablador-token-generator

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+

## Installation

```bash
# Add the repository (if published)
helm repo add helmholtzai-fzj https://helmholtzai-fzj.github.io/blablador-token-generator
helm repo update

# Install the chart
helm install token-generator helmholtzai-fzj/blablador-token-generator
```

## Development/Local Installation

```bash
# Build Docker image
docker build -t ghcr.io/helmholtzai-fzj/blablador-token-generator:latest .

# Push to registry
docker push ghcr.io/helmholtzai-fzj/blablador-token-generator:latest

# Install locally
cd helm/blablador-token-generator
helm install token-generator .
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Docker image | `ghcr.io/helmholtzai-fzj/blablador-token-generator` |
| `image.tag` | Image tag | `latest` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `ingress.enabled` | Enable ingress | `true` |
| `persistence.enabled` | Enable PVC for DB | `true` |
| `persistence.size` | PVC size | `1Gi` |

### OAuth Configuration

Edit `values.yaml` or set via CLI:

```bash
helm install token-generator . \
  --set config.oauth.client_id=your-client-id \
  --set config.oauth.client_secret=your-secret \
  --set config.oauth.redirect_uri=https://your-domain/oauth/openid/callback \
  --set config.admin.admin_emails[0]=admin@example.com \
  --set config.admin.admin_emails[1]=another-admin@example.com
```

## Upgrading

```bash
helm upgrade token-generator helmholtzai-fzj/blablador-token-generator
```

## Uninstall

```bash
helm uninstall token-generator
```

Note: This will not delete the PersistentVolumeClaim. Delete it manually if needed:
```bash
kubectl delete pvc token-generator-db
```