FROM denoland/deno:alpine

EXPOSE 80

WORKDIR /app

COPY . .

RUN deno cache deps.js

CMD [ "run", "--unstable", "--watch", "--allow-net", "--allow-read", "--allow-write", "--allow-env", "--no-check", "app.js" ]
