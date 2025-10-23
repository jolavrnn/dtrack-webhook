# DTrack Webhook

A robust Go-based tool for processing Software Bill of Materials (SBOM) files and integrating with [Dependency-Track](https://dependencytrack.org/).  
Supports multiple SBOM formats (CycloneDX, SPDX, Trivy Operator) with optimized handling for Kubernetes and Trivy Operator outputs.

## Features

- **Multi-Format Support** – CycloneDX, SPDX, and Trivy Operator formats  
- **Kubernetes Optimized** – Enhanced handling for TrivyOperator SBOMs from clusters  
- **Robust Error Handling** – Fallback strategies for missing project metadata  
- **Normalization** – Cleans and normalizes SBOM components and metadata  
- **Metrics** – Counts components and dependencies with detailed logs  
- **Dependency-Track Integration** – Full webhook and API integration  
- **Health Checks** – Built-in `/health` endpoint  
- **Structured Logging** – ECS-compatible format  

## Quick Start with Docker Compose

### Simple Setup

```bash
docker compose up -d
```

### Full Example

```yaml
version: '3.8'

services:
  dtrack-webhook:
    build: .
    container_name: dtrack-webhook
    environment:
      PORT: 8081
      DTRACK_URL: http://dependencytrack-apiserver:8080
      DTRACK_API_KEY: your-dtrack-api-key-here
      DT_PROJECT_NAME: "[[.sbomReport.report.artifact.repository]]"
      DT_PROJECT_VERSION: "[[.sbomReport.report.artifact.tag]]"
      DT_PROJECT_TAGS: "webhook,automated"
      DT_PROJECT_PARENT: "develop"
      LOG_LEVEL: info
      LOG_FORMAT: ecs
    ports:
      - "8082:8081"
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8081/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - dtrack-net
    restart: unless-stopped

  dependencytrack-apiserver:
    image: dependencytrack/apiserver:latest
    container_name: dtrack-apiserver
    environment:
      - ALPINE_DATABASE_MODE=embedded
      - ALPINE_DATABASE_URL=jdbc:h2:mem:.//opt/h2;mode=PostgreSQL
    ports:
      - "8080:8080"
    networks:
      - dtrack-net
    restart: unless-stopped

  dependencytrack-frontend:
    image: dependencytrack/frontend:latest
    container_name: dtrack-frontend
    environment:
      - API_BASE_URL=http://dtrack-apiserver:8080
    ports:
      - "8085:8080"
    depends_on:
      - dtrack-apiserver
    networks:
      - dtrack-net
    restart: unless-stopped

networks:
  dtrack-net:
    driver: bridge
```

## Environment Variables

| Variable | Description | Default |
|-----------|--------------|----------|
| `PORT` | Webhook server port | 8081 |
| `DTRACK_URL` | Dependency-Track API server URL | **Required** |
| `DTRACK_API_KEY` | Dependency-Track API key | **Required** |
| `DT_PROJECT_NAME` | Project name template | `[[.sbomReport.report.artifact.repository]]` |
| `DT_PROJECT_VERSION` | Project version template | `[[.sbomReport.report.artifact.tag]]` |
| `DT_PROJECT_TAGS` | Comma-separated project tags | Optional |
| `DT_PROJECT_PARENT` | Parent project name | Optional |
| `LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `LOG_FORMAT` | Log format (`text`, `json`, `ecs`) | `ecs` |

## Running Services

```bash
# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs dtrack-webhook

# Stop services
docker compose down
```

## Manual Installation

### Download Pre-built Binaries

#### Linux AMD64
```bash
wget https://github.com/jolavrnn/dtrack-webhook/releases/download/v1.0.0/dtrack-webhook-linux-amd64
chmod +x dtrack-webhook-linux-amd64
sudo mv dtrack-webhook-linux-amd64 /usr/local/bin/dtrack-webhook
```

#### Linux ARM64
```bash
wget https://github.com/jolavrnn/dtrack-webhook/releases/download/v1.0.0/dtrack-webhook-linux-arm64
chmod +x dtrack-webhook-linux-arm64
sudo mv dtrack-webhook-linux-arm64 /usr/local/bin/dtrack-webhook
```

#### macOS AMD64
```bash
wget https://github.com/jolavrnn/dtrack-webhook/releases/download/v1.0.0/dtrack-webhook-darwin-amd64
chmod +x dtrack-webhook-darwin-amd64
sudo mv dtrack-webhook-darwin-amd64 /usr/local/bin/dtrack-webhook
```

#### macOS ARM64 (Apple Silicon)
```bash
wget https://github.com/jolavrnn/dtrack-webhook/releases/download/v1.0.0/dtrack-webhook-darwin-arm64
chmod +x dtrack-webhook-darwin-arm64
sudo mv dtrack-webhook-darwin-arm64 /usr/local/bin/dtrack-webhook
```

#### Windows AMD64
```bash
curl -LO https://github.com/jolavrnn/dtrack-webhook/releases/download/v1.0.0/dtrack-webhook-windows-amd64.exe
```
## Docker Standalone

```bash
docker run -d   -p 8082:8081   -e DTRACK_URL=http://your-dtrack-server:8080   -e DTRACK_API_KEY=your-api-key   -e DT_PROJECT_TAGS="webhook,automated"   -e LOG_LEVEL=info   ghcr.io/jolavrnn/dtrack-webhook:latest
```

## Usage

### Webhook Server Mode (Recommended)

```bash
export DTRACK_URL=http://localhost:8080
export DTRACK_API_KEY=your-api-key

dtrack-webhook server
```

Or using CLI flags:

```bash
dtrack-webhook server   --port 8081   --dtrack-url http://localhost:8080   --dtrack-api-key your-api-key   --verbose
```

### Processing Individual SBOM Files

```bash
# Process a single SBOM file
dtrack-webhook process -i sbom.json -o processed-sbom.json

# Process with custom project naming
dtrack-webhook process   -i trivy-sbom.json   -o output.json   -n "my-application"   -v "1.0.0"   --verbose

# Process a directory of SBOM files
dtrack-webhook process-dir -i ./sboms/ -o ./processed/
```

## Command Line Help

```bash
dtrack-webhook server --help
dtrack-webhook process --help
dtrack-webhook process-dir --help
```

## Webhook API

### Health Check
```bash
curl http://localhost:8081/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Webhook Endpoint
```bash
curl -X POST http://localhost:8081/webhook   -H "Content-Type: application/json"   -d @sbom.json
```

Or directly from Trivy:
```bash
trivy image --format cyclonedx your-image:tag |   curl -X POST http://localhost:8081/webhook     -H "Content-Type: application/json"     -d @-
```

## Example Response

```json
{
  "status": "success",
  "project_name": "my-application",
  "project_version": "1.0.0",
  "components_processed": 150,
  "message": "SBOM processed and uploaded to Dependency-Track"
}
```

## Kubernetes Example (Trivy Operator Integration)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dtrack-webhook
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dtrack-webhook
  template:
    metadata:
      labels:
        app: dtrack-webhook
    spec:
      containers:
      - name: dtrack-webhook
        image: ghcr.io/jolavrnn/dtrack-webhook:latest
        ports:
        - containerPort: 8081
        env:
        - name: DTRACK_URL
          value: "http://dependencytrack-apiserver:8080"
        - name: DTRACK_API_KEY
          valueFrom:
            secretKeyRef:
              name: dtrack-secrets
              key: api-key
        - name: DT_PROJECT_TAGS
          value: "kubernetes,trivy-operator"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
```

## CI/CD Example (GitHub Actions)

```yaml
name: Security Scan & SBOM Upload
on:
  push:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Generate SBOM with Trivy
        run: |
          docker run --rm             -v /var/run/docker.sock:/var/run/docker.sock             aquasec/trivy:latest             image --format cyclonedx my-app:${{ github.sha }} > sbom.json

      - name: Upload SBOM to Dependency-Track via Webhook
        run: |
          curl -X POST http://your-dtrack-webhook:8081/webhook             -H "Content-Type: application/json"             -d @sbom.json
```

## Project Name Handling

| Template | Description |
|-----------|--------------|
| `[[.sbomReport.report.artifact.repository]]` | Image repository name |
| `[[.sbomReport.report.artifact.tag]]` | Image tag |
| `[[.metadata.name]]` | Kubernetes resource name |
| `[[.metadata.namespace]]` | Kubernetes namespace |

**Fallback Order:**
1. Template extraction  
2. Artifact repository  
3. Kubernetes metadata  
4. CycloneDX components  
5. Generated name  

## Supported SBOM Formats

- CycloneDX (JSON)
- SPDX (JSON)
- Trivy Operator (CycloneDX CRD)

## Monitoring

- `/health` endpoint for:
  - Docker healthchecks  
  - Kubernetes liveness/readiness probes  
  - Load balancer monitoring  

## Logging (ECS Format)

```json
{
  "@timestamp": "2025-01-15T10:30:00.000Z",
  "log.level": "INFO",
  "message": "SBOM processed successfully",
  "ecs.version": "1.6.0",
  "service.name": "dtrack-webhook",
  "event.dataset": "dtrack-webhook.webhook",
  "project.name": "my-application",
  "project.version": "1.0.0",
  "components.count": 150
}
```

## Troubleshooting

### Common Issues

**Failed to connect to Dependency-Track**  
- Verify `DTRACK_URL` and network access  
- Check API key permissions  

**Project name is empty**  
- Check SBOM metadata  
- Verify template variables  
- Use debug logs  

**Invalid SBOM format**  
- Ensure valid JSON  
- Conform to CycloneDX/SPDX schema  

Enable debug logging:
```bash
export LOG_LEVEL=debug
dtrack-webhook server --verbose
```

## Development

```bash
git clone https://github.com/jolavrnn/dtrack-webhook
cd dtrack-webhook

# Build binary
go build -o dtrack-webhook cmd/main.go

# Build Docker image
docker build -t dtrack-webhook .
```

### Run Tests

```bash
go test ./... -v
```

---
