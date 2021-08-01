#!make

DOCKER?=docker
DOCKER_BUILD_FLAGS?=
DOCKER_REGISTRY?=docker.io
DOCKER_TAG?=2.0.0
GIT?=git
PY3?=python3
DATE=$(shell date +%s)
TMP_GIT=tmp-$(shell date +%s)

define HELP_MENU
	Usage: make [<env>] <target> [<target> ...]

	Main targets:
		all (default)   call the default target(s)
		build           build the Docker image
		clean           remove all default artifacts
		help            show this help
		save            save the Docker image to an archive
		rulesets		update default rulesets (files will be created in current directory)

	Refer to the documentation for use cases and examples.
endef

.PHONY: all build clean help save

all: clean

build:
ifndef DOCKER
	$(error Docker (https://docs.docker.com/install/) is required. Please install it first)
endif
	$(DOCKER) image build \
		--rm \
		--tag $(DOCKER_REGISTRY)/wagga40/zircolite:$(DOCKER_TAG) \
		$(DOCKER_BUILD_FLAGS) \
		.

help:
	$(info $(HELP_MENU))

clean:
	rm -rf "detected_events.json"
	rm -rf ./tmp-*
	rm -f zircolite.log
	rm -f fields.json
	rm -f zircolite.tar

save:
ifndef DOCKER
	$(error Docker (https://docs.docker.com/install/) is required. Please install it first)
endif
	$(DOCKER) image save \
		--output zircolite.tar \
		$(DOCKER_REGISTRY)/wagga40/zircolite:$(DOCKER_TAG)

rulesets:
ifndef GIT
	$(error Git is required. Please install it first)
endif
ifndef PY3
	$(error Python3 is required. Please install it first)
endif
	$(GIT) clone https://github.com/SigmaHQ/sigma.git $(TMP_GIT)
	$(PY3) tools/genRules/genRules.py --rulesdirectory=$(TMP_GIT)/rules/windows/ --config=tools/genRules/config/generic.yml --sigmac=$(TMP_GIT)/tools/sigmac --output=rules_windows_generic_$(DATE).json
	$(PY3) tools/genRules/genRules.py --rulesdirectory=$(TMP_GIT)/rules/windows/ --config=tools/genRules/config/sysmon.yml --sigmac=$(TMP_GIT)/tools/sigmac --output=rules_windows_sysmon_$(DATE).json
	rm -rf $(TMP_GIT)
