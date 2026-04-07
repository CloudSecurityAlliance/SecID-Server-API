# Docker Deployment

Planned. Will provide Dockerfiles for both Python and TypeScript servers, plus a docker-compose.yml with optional Redis.

```bash
# Target usage:
docker run -p 8000:8000 -v ./SecID/registry:/data/registry ghcr.io/cloudsecurityalliance/secid-server-api

# With Redis:
docker compose up
```
