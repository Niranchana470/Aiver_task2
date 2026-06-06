# Offensive Security Agent - Dockerfile
# Production-ready container with agentic security scanning capabilities

# Use Python 3.14 slim image
FROM python:3.14-slim

# Set metadata
LABEL maintainer="Niranchana470"
LABEL description="Agentic Offensive Security Agent for AWS Infrastructure Security Scanning"
LABEL version="2.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Application directories
    APP_DIR=/app \
    LOGS_DIR=/app/logs \
    REPORTS_DIR=/app/reports \
    CONFIG_DIR=/app/config \
    # Python path
    PYTHONPATH=/app:$PYTHONPATH

# Create app directory
WORKDIR $APP_DIR

# Create necessary directories
RUN mkdir -p $LOGS_DIR $REPORTS_DIR $CONFIG_DIR

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt requirements-agentic.txt ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements-agentic.txt && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 securityagent && \
    chown -R securityagent:securityagent $APP_DIR

# Switch to non-root user
USER securityagent

# Set up entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Starting Offensive Security Agent..."\n\
echo "========================================"\n\
echo "Version: 2.0.0 (Agentic Architecture)"\n\
echo "AI Provider: ${AI_PROVIDER:-mock}"\n\
echo "AWS Region: ${AWS_REGION:-us-east-1}"\n\
echo "========================================"\n\
\n\
# Run the agentic security scanner\n\
exec python main_agentic.py "$@"\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose volume directories for persistence
VOLUME [$LOGS_DIR, $REPORTS_DIR, $CONFIG_DIR]

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (can be overridden)
CMD ["--config", "config/agentic_config.yaml"]
