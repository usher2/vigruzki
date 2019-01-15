FROM alpine:3.6

LABEL maintainer="Phil Kulin <schors@gmail.com>"

WORKDIR /tmp

RUN apk add --no-cache bash openssl uwsgi-python3 mariadb-client-libs py3-msgpack \
        lz4-libs libattr libacl ca-certificates \
        && pip3 install --upgrade pip \
        && apk add --no-cache --virtual .build-deps \
                mariadb-dev \
                python3-dev \
                gcc \
                musl-dev \
        && pip3 install mysqlclient \
        && apk del .build-deps 

RUN apk add --no-cache --virtual .build-deps \
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
        && pip3 install flask \
        && pip3 install flask-mysqldb \
        && addgroup -S -g 82 www-data \
        && adduser -D -S -h /var/www -G www-data -u 82 -s /sbin/nologin www-data \
        && addgroup eais -g 2002 \
        && adduser -D -h /srv/eais -G eais -u 2002 -s /bin/bash eais \
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

COPY upload.py /srv/eais/

EXPOSE 5000
ENV UPLOAD_SETTINGS=/upload.cfg

CMD ["uwsgi", "--plugin", "python3", "--socket", ":5000", "--uid", "eais", "--gid", "eais", "--wsgi-file", "/srv/eais/upload.py", "--callable", "app", "--process", "30"]

