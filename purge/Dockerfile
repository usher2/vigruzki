FROM alpine:3.6

LABEL maintainer="Phil Kulin <schors@gmail.com>"

WORKDIR /tmp
RUN apk add --no-cache bash openssl python3 py3-msgpack mariadb-client-libs\
        lz4-libs libattr libacl libressl ca-certificates \
        && pip3 install --upgrade pip \
        && apk add --no-cache --virtual .build-deps \
                gcc libc-dev make pcre-dev zlib-dev \
                python3-dev lz4-dev acl-dev attr-dev libressl-dev linux-headers \
                mariadb-dev \
                musl-dev \
                curl \
        && pip3 install mysqlclient \
        && curl https://files.pythonhosted.org/packages/3a/5c/af593739e5ea8dfe81f76068db07991bba4c61d13ba1206e6e5dc389decb/borgbackup-1.1.0b6.tar.gz#md5=008d588e841835e9f28e2c68e5c6e848 | tar --strip-components=1 -zxp \
        && curl https://github.com/borgbackup/borg/commit/019a2587092ca785244e1f37067a96f614b51ac4.patch | patch -p 1 \
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

