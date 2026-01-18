ARG PYTHON_VERSION="3.14-slim"

FROM python:${PYTHON_VERSION}

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"
ARG ZIRCOLITE_REQUIREMENTS_FILE="requirements.txt"

LABEL org.opencontainers.image.title="Zircolite" \
      org.opencontainers.image.description="A standalone SIGMA-based detection tool for EVTX, Auditd and Sysmon for Linux logs" \
      org.opencontainers.image.authors="wagga40" \
      org.opencontainers.image.source="https://github.com/wagga40/Zircolite"

WORKDIR ${ZIRCOLITE_INSTALL_PREFIX}/zircolite

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy and install Python dependencies
COPY ${ZIRCOLITE_REQUIREMENTS_FILE} .
RUN pip install --no-cache-dir -r ${ZIRCOLITE_REQUIREMENTS_FILE} && \
    rm -rf ~/.cache/pip

# Copy static assets
COPY templates/ templates/
COPY config/ config/
COPY rules/ rules/
COPY gui/ gui/

# Copy application code 
COPY zircolite/ zircolite/
COPY zircolite.py .

# Set permissions and update rules in single layer
RUN chmod 0755 zircolite.py && \
    python3 zircolite.py -U

ENTRYPOINT ["python3", "zircolite.py"]
CMD ["--help"]
