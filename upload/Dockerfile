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
        && curl https://files.pythonhosted.org/packages/3a/5c/af593739e5ea8dfe81f76068db07991bba4c61d13ba1206e6e5dc389decb/borgbackup-1.1.0b6.tar.gz#md5=008d588e841835e9f28e2c68e5c6e848 | tar --strip-components=1 -zxp \
        && curl https://github.com/borgbackup/borg/commit/019a2587092ca785244e1f37067a96f614b51ac4.patch | patch -p 1 \
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

