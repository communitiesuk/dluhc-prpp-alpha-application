FROM python:3.8-slim-buster
WORKDIR /opt/idam
RUN mkdir -p /opt/idam /var/log/idam


COPY . /opt/idam

RUN pip install --upgrade pip

RUN apt-get update; apt-get install curl -y

RUN pip install -r requirements.txt --no-cache-dir

RUN adduser --disabled-password --system -uid 1001 --shell /bin/sh idam
RUN chown -R 1001:1001 /opt/idam /var/log/idam
RUN chmod +x /opt/idam/docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/opt/idam/docker-entrypoint.sh"]
