FROM node:20-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV PORT=3000
ENV DATA_DIR=/app/data
RUN mkdir -p /app/data
EXPOSE 3000
CMD ["npm","start"]
