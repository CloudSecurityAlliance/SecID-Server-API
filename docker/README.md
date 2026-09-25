# Docker Deployment

Planned, not started. There is no Dockerfile yet and **no image is published**: the `ghcr.io` name below is the intended target, not something you can pull today. It will provide Dockerfiles for the Python server (and the TypeScript server when it exists), plus a docker-compose.yml with optional Redis.

```bash
# Target usage (not available yet):
docker run -p 8000:8000 -v ./SecID/registry:/data/registry ghcr.io/cloudsecurityalliance/secid-server-api

# With Redis:
docker compose up
```
