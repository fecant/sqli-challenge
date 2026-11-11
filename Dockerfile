# CTF 动态题镜像：一关一容器
# 构建：docker build --platform linux/amd64 -t <user>/sqli-challenge:<tag> .
# 运行：docker run -e LEVEL=1 -e CTF_FLAG=flag{xxx} -p 3000:3000 <user>/sqli-challenge:<tag>
FROM node:22-alpine

# alpine 上跑 sql.js（wasm）无需额外依赖，纯 JS + WebAssembly
WORKDIR /app

# 先装依赖，利用 Docker 层缓存
COPY package.json package-lock.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

# 默认单关卡容器；平台会在额外环境变量里指定 LEVEL 和注入 flag
ENV NODE_ENV=production
EXPOSE 3000

# 必须绑 0.0.0.0，否则平台反代探测不到
CMD ["node", "server.js"]
