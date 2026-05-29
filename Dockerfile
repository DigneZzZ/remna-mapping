FROM node:20-alpine
WORKDIR /app

# Zero runtime dependencies — just copy the source.
COPY server.js ./
COPY public ./public

ENV PORT=8088
ENV DOH=1
ENV DNS_TIMEOUT_MS=4000

EXPOSE 8088
CMD ["node", "server.js"]
