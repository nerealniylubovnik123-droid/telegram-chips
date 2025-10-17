FROM node:20-alpine

WORKDIR /app

# 1) ставим зависимости по lock-файлу
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# 2) копируем остальной код (node_modules НЕ копируем — .dockerignore защитит)
COPY . .

ENV PORT=3000
EXPOSE 3000

CMD ["npm","start"]

