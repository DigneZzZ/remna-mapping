FROM node:20-alpine
WORKDIR /app

# Zero runtime dependencies — just copy the source.
COPY server.js ./
COPY public ./public

# Inside the container the app must listen on all interfaces for Docker's port
# mapping to reach it. Restrict WHO can reach it on the host via the compose
# `ports:` mapping (it binds to 127.0.0.1 by default), not by changing this.
ENV HOST=0.0.0.0
ENV PORT=8088
ENV DOH=1
ENV DNS_TIMEOUT_MS=4000

EXPOSE 8088
CMD ["node", "server.js"]
