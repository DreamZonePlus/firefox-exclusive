FROM node:22-alpine

# .mjs لضمان معاملة الملف كـ ES Module في أي سياق (بلا حاجة إلى package.json).
COPY gateway.mjs /app/gateway.mjs

ENV LISTEN_PORT=8080
EXPOSE 8080

USER node
CMD ["node", "/app/gateway.mjs"]
