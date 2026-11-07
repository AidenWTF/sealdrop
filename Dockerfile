FROM node:22-alpine
RUN apk add --no-cache ffmpeg libqrencode-tools && mkdir /data && chown node:node /data
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
ENV HOST=0.0.0.0 PORT=18446 DATA_DIR=/data
USER node
EXPOSE 18446
CMD ["node", "src/main.js"]
