FROM mcr.microsoft.com/playwright/python:v1.50.0-noble
WORKDIR /service
COPY pyproject.toml ./
RUN pip install --no-cache-dir .
COPY capture.py ./
RUN useradd --create-home --uid 10002 capture-worker && mkdir -p /artifacts && chown capture-worker:capture-worker /artifacts
USER capture-worker
ENTRYPOINT ["python", "capture.py"]

