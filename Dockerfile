FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app
COPY package.json package-lock.json ./
# Only the runtime dependency, without scripts or the npm cache, to keep the image small.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY server.js ./
COPY lib ./lib
COPY scripts ./scripts
COPY public ./public

# The data directory belongs to the unprivileged user, so a named volume
# mounted there starts out writable.
RUN mkdir /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"

CMD ["node", "server.js"]
