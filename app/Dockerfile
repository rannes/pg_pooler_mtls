FROM python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UI_PORT=8080
WORKDIR /srv
COPY app/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
COPY --chown=10001:10001 app /srv/app

FROM base AS test
COPY app/requirements-dev.txt /srv/requirements-dev.txt
RUN pip install --no-cache-dir -r /srv/requirements-dev.txt
COPY --chown=10001:10001 tests/test_app.py /srv/tests/test_app.py
USER 10001:10001
CMD ["python", "-m", "pytest", "tests/test_app.py", "-q", "-p", "no:cacheprovider"]

FROM base AS runtime
USER 10001:10001
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${UI_PORT:-8080} --no-proxy-headers"]
