FROM nginx:alpine

VOLUME /tmp

LABEL maintainer="Phil Kulin <schors@gmail.com>"

RUN adduser -D -S -h /var/www -G www-data -u 82 -s /sbin/nologin www-data \
        && chown -R www-data:www-data /var/cache/nginx

COPY default.conf /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

