# Wayzgoose for Pressable, self-hosted. Builds a small image that runs the
# dashboard + scheduler. See docker-compose.yml and .env.example.
FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production \
    WAYZGOOSE_DATA_DIR=/data \
    PORT=8080 \
    HOST=0.0.0.0

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY src ./src
COPY scripts ./scripts

RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "src/server/server.js"]
