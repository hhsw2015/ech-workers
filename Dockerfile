FROM node:20-alpine3.20

WORKDIR /tmp

COPY start.sh ./

EXPOSE 3000

RUN apk update && apk add --no-cache bash openssl curl &&\
    chmod +x index.js &&\
    npm install

CMD ["bash", "start.sh"]
