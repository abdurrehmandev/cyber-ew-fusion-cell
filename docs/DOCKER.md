# Deploying Cyber-EW Fusion Cell with Docker

This guide covers building and running the application inside Docker for reproducible deployment.

## Prerequisites
- Docker Engine (20.x) installed
- docker-compose (optional, though included in recent Docker Desktop)

## Build & Run (single host)

From the repository root:

```bash
# Build the image
docker-compose build

# Start the service
docker-compose up -d

# Check logs
docker-compose logs -f fusion-cell
```

## Volumes
- Local `./data` is mounted into the container at `/app/data`.
  - `data/inputs/live` — drop telemetry files here
  - `data/outputs/alerts.jsonl` — exported alerts
  - `data/state/` — persisted behavior and correlation indices

## Environment
- NODE_ENV=production is set by docker-compose.yml

## Production Notes
- Allocate persistent storage for data volume
- Use Swarm/Kubernetes for high availability
- For high throughput, adjust ingestWorker polling and consider using batched writes

## Debugging
- Enter container shell:
  ```bash
  docker-compose exec fusion-cell /bin/sh
  ```
- Inspect files at `/app/data`

## Building a smaller runtime image
- Build artifacts then create a smaller runtime image using `node:20-slim` and copy `dist/` only.

