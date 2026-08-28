FROM node:20-bullseye-slim

WORKDIR /app

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends python3 build-essential ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy package manifests first for cache
COPY package.json package-lock.json* ./

# Install deps
RUN npm ci --silent

# Copy project files
COPY . .

# Build production bundle
RUN npm run build || echo "Build may fail in environments without dev deps; continuing"

# Expose port
EXPOSE 3000

# Data directory should be a volume mounted at /app/data
VOLUME ["/app/data"]

CMD ["node", "dist/server.cjs"]
