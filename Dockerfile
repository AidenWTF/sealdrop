FROM node:22-alpine
RUN apk add --no-cache ffmpeg libqrencode-tools rsvg-convert font-dejavu && mkdir /data && chown node:node /data
WORKDIR /app
COPY package.json package-lock.json ./
# Exact versions from the lockfile, without install scripts.
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src ./src
COPY public ./public
ENV HOST=0.0.0.0 PORT=18446 DATA_DIR=/data
USER node
EXPOSE 18446
CMD ["node", "src/main.js"]
