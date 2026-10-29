FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js ./
COPY public ./public
COPY scripts ./scripts
COPY cli/package.json cli/drop.mjs ./cli/
RUN node scripts/pack-cli.mjs
ENV PORT=3000
EXPOSE 3000
USER node
CMD ["node", "server.js"]
