# Since `evtx_dump` precompiled binaries are not shipped with musl support, we need to use the
# Debian-based Python image instead of the Alpine-based image, which increases the size of the
# final image (~70 MB overhead).
#
ARG PYTHON_VERSION="3.11-slim"

FROM "python:${PYTHON_VERSION}" AS stage

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"
ARG ZIRCOLITE_REPOSITORY_URI="https://github.com/wagga40/Zircolite.git"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install --yes --no-install-recommends \
        git && \
    apt-get autoremove --purge --yes && \
    rm -rf /var/lib/apt/lists/*

WORKDIR "${ZIRCOLITE_INSTALL_PREFIX}"

RUN git clone \
        "${ZIRCOLITE_REPOSITORY_URI}" \
        zircolite

WORKDIR "${ZIRCOLITE_INSTALL_PREFIX}/zircolite"

RUN chmod 0755 \
        zircolite.py

FROM "python:${PYTHON_VERSION}"

LABEL author="wagga40"
LABEL description="A standalone SIGMA-based detection tool for EVTX, Auditd and Sysmon for Linux logs."
LABEL maintainer="wagga40"

ARG ZIRCOLITE_INSTALL_PREFIX="/opt"

WORKDIR "${ZIRCOLITE_INSTALL_PREFIX}"

COPY --chown=root:root --from=stage \
         "${ZIRCOLITE_INSTALL_PREFIX}/zircolite" \
         zircolite

WORKDIR "${ZIRCOLITE_INSTALL_PREFIX}/zircolite"

RUN python3 -m pip install \
        --requirement requirements.full.txt

RUN python3 zircolite.py -U

ENTRYPOINT [ "python3", "zircolite.py" ]

CMD [ "--help" ]
