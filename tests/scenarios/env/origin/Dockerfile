FROM python:3.13.9-alpine3.22

RUN apk add --no-cache openssl
COPY server.py /server.py
EXPOSE 8080 8443 8081 8888
HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
    CMD wget -q -O- http://127.0.0.1:8080/small >/dev/null
ENTRYPOINT ["python", "/server.py"]
