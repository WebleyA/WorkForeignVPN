FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server.py index.html ./

USER 65534:65534
EXPOSE 8765

ENTRYPOINT ["python", "server.py"]
CMD ["--host", "0.0.0.0", "--port", "8765"]
