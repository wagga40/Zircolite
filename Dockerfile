ARG PYTHON_VERSION="3.13-slim"

FROM python:${PYTHON_VERSION}

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"
ARG ZIRCOLITE_REQUIREMENTS_FILE="requirements.full.txt"

WORKDIR ${ZIRCOLITE_INSTALL_PREFIX}/zircolite

# Copy requirements first to leverage Docker cache
COPY ${ZIRCOLITE_REQUIREMENTS_FILE} .
RUN pip install --no-cache-dir -r ${ZIRCOLITE_REQUIREMENTS_FILE}

# Install git only when needed for rule updates
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy files in order of change frequency (least to most)
COPY README.md .
COPY docs/ docs/
COPY pics/ pics/
COPY templates/ templates/
COPY config/ config/
COPY bin/ bin/
COPY gui/ gui/
COPY rules/ rules/
COPY zircolite.py .

LABEL author="wagga40" \
    description="A standalone SIGMA-based detection tool for EVTX, Auditd and Sysmon for Linux logs." \
    maintainer="wagga40"

RUN chmod 0755 zircolite.py && \
    python3 zircolite.py -U

ENTRYPOINT ["python3", "zircolite.py"]
CMD ["--help"]
