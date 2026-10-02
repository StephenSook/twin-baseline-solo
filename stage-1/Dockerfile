FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production UV_THREADPOOL_SIZE=8 PORT=8080
COPY server.js ./
EXPOSE 8080
USER node
CMD ["node", "server.js"]
