# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=10001:10001 src/ ./src/
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
# One worker keeps the in-memory incident store consistent; threads serve requests.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--access-logfile", "-", "src.wsgi:app"]
