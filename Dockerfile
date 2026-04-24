# node:18-bullseye — full Debian Bullseye base, introduces some OS-level CVEs
# intentionally not distroless/slim for demo scanning purposes
FROM node:18-bullseye

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "app.js"]
