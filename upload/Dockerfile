FROM ubuntu:bionic

LABEL maintainer="Phil Kulin <schors@gmail.com>"

VOLUME /tmp
WORKDIR /tmp

RUN apt-get update && apt-get dist-upgrade -y \
        && apt-get install -y --no-install-recommends bash openssl libengine-gost-openssl1.1 wget curl \
        python3-pip liblz4-tool libattr1 libacl1 ca-certificates libmariadbd18 \
        && pip3 install --upgrade pip \
        && apt-get install -y --no-install-recommends python3-dev libmariadbd-dev gcc musl-dev \
        libc-dev make libpcre2-dev zlib1g-dev liblz4-dev acl-dev libattr1-dev libacl1-dev libssl-dev \
        && pip install setuptools \
        && pip install mysqlclient \
        && pip install msgpack-python \
        && pip install python-dateutil \
        && curl -L https://github.com/borgbackup/borg/releases/download/1.1.8/borgbackup-1.1.8.tar.gz | tar --strip-components=1 -zxp \
        && pip install . \
        && pip install uWSGI \
        && pip install flask \
        && pip install flask-mysqldb \
        && apt-get remove -y python3-dev libmariadbd-dev gcc musl-dev \
        libc-dev make libpcre2-dev zlib1g-dev liblz4-dev acl-dev libattr1-dev libacl1-dev libssl-dev \
        && groupadd -r -g 82 www1-data \
#        && addgroup -S -g 82 www-data \
        && useradd -r -d /var/www -g www1-data -u 82 -s /sbin/nologin www1-data \
#        && adduser -D -S -h /var/www -G www-data -u 82 -s /sbin/nologin www-data \
        && groupadd -g 2002 eais \
#        && addgroup eais -g 2002 \
        && useradd -m -d /srv/eais -g eais -u 2002 -s /bin/bash eais \
#        && adduser -D -h /srv/eais -G eais -u 2002 -s /bin/bash eais \
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
        && chown eais:eais /var/log/eais \
        && rm -rf /tmp/*

COPY upload.py /srv/eais/

EXPOSE 5000
ENV UPLOAD_SETTINGS=/upload.cfg

CMD ["uwsgi", "--plugin", "python3", "--socket", ":5000", "--uid", "eais", "--gid", "eais", "--wsgi-file", "/srv/eais/upload.py", "--callable", "app", "--process", "30"]

