FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_SERVER_PORT=8080 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# PyMySQL is pure Python, so no compiler or MariaDB client headers are needed.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# Keep pip (and the certifi copy it vendors) current: the build is the only
# place pip runs, and an old vendored CA bundle would still trust revoked CAs.
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.1"

# Install python dependencies early to cache them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY app /app
RUN chown -R app:app /app

# Run unprivileged
USER app

# Streamlit port
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, socket; socket.create_connection(('127.0.0.1', int(os.environ.get('STREAMLIT_SERVER_PORT', '8080'))), 3).close()"

CMD ["python", "main.py"]
