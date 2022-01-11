FROM alpine:3.6

LABEL maintainer="Phil Kulin <schors@gmail.com>"

VOLUME /tmp

WORKDIR /tmp
RUN apk add --no-cache bash openssl python3 py3-msgpack mariadb-client-libs \
        lz4-libs libattr libacl libressl ca-certificates \
        && pip3 install --upgrade pip \
        && apk add --no-cache --virtual .build-deps \
                gcc libc-dev make pcre-dev zlib-dev \
                python3-dev lz4-dev acl-dev attr-dev libressl-dev linux-headers \
                mariadb-dev \
                musl-dev \
                curl \
        && pip3 install mysqlclient \
        && curl -L https://github.com/borgbackup/borg/releases/download/1.1.8/borgbackup-1.1.8.tar.gz | tar --strip-components=1 -zxp \
        && pip3 install . \
        && apk del .build-deps \
        && rm -rf /tmp/*

RUN pip3 install python-dateutil \
        && addgroup -S -g 82 www-data \
        && adduser -D -S -h /var/www -G www-data -u 82 -s /sbin/nologin www-data \
        && addgroup eais -g 2002 \
        && adduser -S -h /srv/eais -G eais -u 2002 -s /bin/bash eais \
        && chmod 750 /srv/eais \
        && mkdir -p /var/opt/eais/data \
        && chown eais:eais /var/opt/eais/data \
        && chmod 755 /var/opt/eais/data \
        && mkdir -p /var/opt/eais/tmp \
        && chown eais:eais /var/opt/eais/tmp \
        && chown www-data:eais /var/opt/eais \
        && chmod 170 /var/opt/eais \
        && mkdir -p /var/log/eais \
        && chmod 750 /var/log/eais \
        && chown eais:eais /var/log/eais

ENV UPLOAD_SETTINGS=/upload.cfg
ENV MYSQL_CONFIG=/mysql_user.env

COPY purge.py /srv/eais/
COPY cron_entrypoint.sh /entrypoint.sh
COPY crontab /etc/crontabs/eais

ENTRYPOINT ["/entrypoint.sh"]
CMD [ "crond", "-f", "-d", "8"]
