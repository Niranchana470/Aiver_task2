# Offensive Security Agent - Docker Deployment

This guide covers Docker deployment of the Agentic Offensive Security Agent.

## Quick Start

### 1. Build the Docker Image

```bash
docker build -t offensive-security-agent:latest .
```

### 2. Run with Mock AI Provider (No API Keys Required)

```bash
docker run --rm \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest
```

### 3. Run with Real AI Provider

```bash
# Using OpenAI
docker run --rm \
  -e AI_PROVIDER=openai \
  -e OPENAI_API_KEY="sk-..." \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest

# Using Anthropic
docker run --rm \
  -e AI_PROVIDER=anthropic \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest
```

## Docker Compose (Recommended)

### Setup Environment Variables

Create a `.env` file in the project root:

```bash
# AI Provider
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here

# AWS Configuration
AWS_PROFILE=default
AWS_REGION=us-east-1

# Logging
LOG_LEVEL=INFO
DEBUG=false
```

### Run with Docker Compose

```bash
# Run the security scanner
docker-compose up

# Run tests
docker-compose --profile test up

# Build and run in one command
docker-compose up --build

# Run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AI_PROVIDER` | AI provider to use (mock, openai, anthropic) | `mock` | No |
| `OPENAI_API_KEY` | OpenAI API key for GPT-4 | - | Yes (if using openai) |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | - | Yes (if using anthropic) |
| `AWS_PROFILE` | AWS profile name | `default` | No |
| `AWS_REGION` | AWS region | `us-east-1` | No |
| `AWS_ACCESS_KEY_ID` | AWS access key (override profile) | - | No |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key (override profile) | - | No |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` | No |
| `DEBUG` | Enable debug mode | `false` | No |

### Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `./config` | `/app/config` | Configuration files (read-only) |
| `./logs` | `/app/logs` | Log files (persistent) |
| `./reports` | `/app/reports` | Scan reports (persistent) |
| `~/.aws/credentials` | `/home/securityagent/.aws/credentials` | AWS credentials (optional) |

## Advanced Usage

### Custom Configuration

```bash
docker run --rm \
  -v $(pwd)/config/custom-config.yaml:/app/config/custom-config.yaml:ro \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest \
  --config /app/config/custom-config.yaml
```

### Interactive Shell

```bash
docker run --rm -it \
  -v $(pwd)/logs:/app/logs \
  --entrypoint /bin/bash \
  offensive-security-agent:latest
```

### Run Specific Checks

```bash
docker run --rm \
  -e AI_PROVIDER=openai \
  -e OPENAI_API_KEY="sk-..." \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest \
  --checks S3SecurityCheck IAMSecurityCheck
```

### Scheduled Scans with Cron

```bash
# Run every 6 hours
docker run --rm \
  --name security-scan \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  offensive-security-agent:latest
```

Add to crontab:
```
0 */6 * * * docker start security-scan
```

## Docker Compose Profiles

### Production Profile

```bash
docker-compose --profile production up
```

### Test Profile

```bash
docker-compose --profile test up
```

### Development Profile

```bash
docker-compose --profile development up
```

## Health Checks

### Check Container Status

```bash
docker ps
docker inspect agentic-security-scanner
```

### View Logs

```bash
# All logs
docker logs agentic-security-scanner

# Follow logs
docker logs -f agentic-security-scanner

# Last 100 lines
docker logs --tail 100 agentic-security-scanner
```

### Check Scan Results

```bash
# List reports
ls -la reports/

# View latest report
cat reports/scan_*.md

# View decision trace
cat logs/decision_trace.md
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs

# Rebuild image
docker-compose build --no-cache

# Check disk space
docker system df
```

### Permission Issues

```bash
# Fix log/report directory permissions
sudo chown -R $USER:$USER logs reports
```

### AWS Credentials Not Found

```bash
# Mount AWS credentials
docker run --rm \
  -v ~/.aws/credentials:/home/securityagent/.aws/credentials:ro \
  -v ~/.aws/config:/home/securityagent/.aws/config:ro \
  offensive-security-agent:latest
```

### AI Provider Errors

```bash
# Verify API key is set
docker run --rm \
  -e AI_PROVIDER=openai \
  -e OPENAI_API_KEY="sk-..." \
  offensive-security-agent:latest \
  python -c "from src.reasoning.ai_provider import create_ai_provider; print(create_ai_provider({'provider': 'openai', 'api_key': 'sk-...'}, None))"
```

## Production Deployment

### Security Best Practices

1. **Use secrets management**: Store API keys in Docker secrets or vault
2. **Run as non-root**: Container runs as `securityagent` user (UID 1000)
3. **Read-only config**: Mount config files as read-only
4. **Resource limits**: CPU and memory limits configured
5. **Network isolation**: Run in isolated Docker network

### Docker Secrets (Swarm)

```bash
# Create secrets
echo "sk-..." | docker secret create openai_api_key -
echo "sk-ant-..." | docker secret create anthropic_api_key -

# Deploy with secrets
docker stack deploy -c docker-compose.yml security-agent
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: openai-secret
type: Opaque
data:
  api-key: c2stLi4u  # base64 encoded
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-agent
  template:
    metadata:
      labels:
        app: security-agent
    spec:
      containers:
      - name: agent
        image: offensive-security-agent:latest
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: openai-secret
              key: api-key
```

## Monitoring

### Container Metrics

```bash
# Container stats
docker stats agentic-security-scanner

# Resource usage
docker top agentic-security-scanner
```

### Log Aggregation

```bash
# Export logs
docker logs agentic-security-scanner > scan.log

# Stream to external service
docker run --rm \
  --log-driver=fluentd \
  --log-opt fluentd-address=localhost:24224 \
  offensive-security-agent:latest
```

## Performance Tuning

### Memory Limits

```bash
docker run --rm \
  --memory="2g" \
  --memory-swap="2g" \
  offensive-security-agent:latest
```

### CPU Limits

```bash
docker run --rm \
  --cpus="2.0" \
  offensive-security-agent:latest
```

### Parallel Execution

```bash
# Adjust worker count
docker run --rm \
  -e MAX_WORKERS=20 \
  offensive-security-agent:latest
```

## Cleanup

### Remove Containers

```bash
docker-compose down
docker rm agentic-security-scanner
```

### Remove Images

```bash
docker rmi offensive-security-agent:latest
```

### Clean All

```bash
docker system prune -a
```

## Support

For issues and questions:
- Check logs: `docker logs agentic-security-scanner`
- Run tests: `docker-compose --profile test up`
- Review config: `config/agentic_config.yaml`
- Check documentation: `docs/`
