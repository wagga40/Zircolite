ARG PYTHON_VERSION="3.14-slim"

# ---- builder ----
FROM python:${PYTHON_VERSION} AS builder

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"
ARG ZIRCOLITE_REQUIREMENTS_FILE="requirements.txt"

# Isolate dependencies in a venv so only resolved packages reach the runtime stage
ENV VIRTUAL_ENV="/opt/venv" \
    PATH="/opt/venv/bin:${PATH}"
RUN python -m venv "${VIRTUAL_ENV}"

WORKDIR ${ZIRCOLITE_INSTALL_PREFIX}/zircolite

# Install dependencies first so this layer is cached across code changes
COPY ${ZIRCOLITE_REQUIREMENTS_FILE} .
RUN pip install --no-cache-dir -r ${ZIRCOLITE_REQUIREMENTS_FILE}

# Static assets and application code
COPY templates/ templates/
COPY config/ config/
COPY rules/ rules/
COPY gui/ gui/
COPY zircolite/ zircolite/
COPY zircolite.py .

# Refresh rulesets at build time (needs network); kept in the builder layer only
RUN python3 zircolite.py -U

# ---- runtime ----
FROM python:${PYTHON_VERSION}

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"

LABEL org.opencontainers.image.title="Zircolite" \
      org.opencontainers.image.description="A standalone SIGMA-based detection tool for EVTX, Auditd and Sysmon for Linux logs" \
      org.opencontainers.image.authors="wagga40" \
      org.opencontainers.image.source="https://github.com/wagga40/Zircolite"

ENV VIRTUAL_ENV="/opt/venv" \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR ${ZIRCOLITE_INSTALL_PREFIX}/zircolite

# The venv symlinks the base interpreter; safe because both stages share the same base image
COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
# Copy the app from the builder so the rulesets refreshed by -U are carried over
COPY --from=builder ${ZIRCOLITE_INSTALL_PREFIX}/zircolite ${ZIRCOLITE_INSTALL_PREFIX}/zircolite

# Run as a non-root user that owns every asset under the install prefix
RUN chmod 0755 zircolite.py && \
    groupadd --system zircolite && \
    useradd --system --gid zircolite --home-dir ${ZIRCOLITE_INSTALL_PREFIX}/zircolite --shell /usr/sbin/nologin zircolite && \
    chown -R zircolite:zircolite ${ZIRCOLITE_INSTALL_PREFIX}/zircolite
USER zircolite

ENTRYPOINT ["python3", "zircolite.py"]
CMD ["--help"]
