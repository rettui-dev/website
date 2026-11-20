# An exact Node.js 24 release (24.7 or later: the login needs its built-in Argon2id, the user store
# node:sqlite), pinned by digest so that every build starts from the same image. To move to a newer
# release, change both: docker buildx imagetools inspect node:24.x.y-alpine gives the digest.
FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5

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

# The data directory belongs to the unprivileged user, so a named volume mounted there starts out
# writable, and only by it: the user store (users.db, with its -wal and -shm files next to it) is
# made there. node:sqlite is built into Node.js; nothing else is needed for it.
RUN mkdir /data && chown node:node /data && chmod 700 /data
USER node
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"

CMD ["node", "server.js"]
