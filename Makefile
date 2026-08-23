# SightingDB: build, and run it locally on Kubernetes.
#
#   make            what each target does
#   make dev        image -> kind cluster -> chart -> smoke test, from nothing
#
# Everything below is overridable: make dev TAG=wip NAMESPACE=sightingdb

IMAGE           ?= sightingdb
TAG             ?= dev
IMAGE_REF       := $(IMAGE):$(TAG)
# Build with vendored OpenSSL: slower, but the image needs no libssl.
FEATURES        ?=

RELEASE         ?= sightingdb
NAMESPACE       ?= sightingdb
KIND_CLUSTER    ?= sightingdb
CHART           := helm/sightingdb
VALUES          ?= $(CHART)/values-local.yaml
HELM_ARGS       ?=
# Port used by `make port-forward` and `make smoke`, on both sides.
PORT            ?= 9999

CARGO           ?= cargo
DOCKER          ?= docker
HELM            ?= helm
KUBECTL         ?= kubectl
KIND            ?= kind

# The cluster everything acts on, resolved once and then passed explicitly to
# every command — so nothing here can be redirected by a `kubectl use-context`
# that happens midway through a target.
CONTEXT         ?= $(shell $(KUBECTL) config current-context 2>/dev/null)

# Contexts these targets are willing to change. This Makefile is for running
# SightingDB on your own machine; a cluster someone depends on is reached with
# helm and kubectl directly, deliberately, not by a make target that follows
# whatever context happens to be current. Override for one command with
# ALLOW_ANY_CONTEXT=1 if you really mean it.
LOCAL_CONTEXTS  ?= docker-desktop rancher-desktop minikube colima kind-% k3d-% k3s-%

KUBE            := $(KUBECTL) --context $(CONTEXT) --namespace $(NAMESPACE)

# The id of the image that is actually built. Rebuilding under the same tag
# leaves the StatefulSet identical, so Kubernetes has no reason to roll and you
# keep looking at the old code; carrying the id as a pod annotation gives it
# one. Recursively expanded, so it is read after `make image` has run rather
# than when this file is parsed.
IMAGE_ID         = $(shell $(DOCKER) image inspect $(IMAGE_REF) --format '{{.Id}}' 2>/dev/null)

HELM_INSTALL     = $(HELM) upgrade --install $(RELEASE) $(CHART) \
                     --kube-context $(CONTEXT) \
                     --namespace $(NAMESPACE) --create-namespace \
                     --values $(VALUES) \
                     --set image.repository=$(IMAGE) --set image.tag=$(TAG) \
                     $(if $(IMAGE_ID),--set podAnnotations.sightingdb-image-id=$(IMAGE_ID),) \
                     $(HELM_ARGS)

.DEFAULT_GOAL := help
.PHONY: help all sightingdb build release test fmt lint check clean \
        image image-push image-exists load deploy kind-up kind-down kind-load \
        install upgrade uninstall local-only \
        status logs port-forward admin-key acl rotate-key smoke chart-test wait \
        refresh restart dev teardown \
        helm-lint helm-template helm-package sync-version

##@ Build

all: build ## Build the debug binary (the historical default target)

build: ## Build the debug binary
	$(CARGO) build

sightingdb: build ## Alias for build, kept from the original Makefile

release: ## Build the optimised binary
	$(CARGO) build --release

test: ## Run the test suite
	$(CARGO) test

fmt: ## Format the source
	$(CARGO) fmt

lint: ## Format check, clippy and the tests, as CI runs them
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) test --locked

check: lint helm-lint ## Everything CI checks, plus the chart

clean: ## Remove build output
	$(CARGO) clean

##@ Container image
#
# Built from this working tree, not from a clone of the repository, so what you
# run is what you are looking at.

image: ## Build the container image from the local source
	$(DOCKER) build -f docker/Dockerfile -t $(IMAGE_REF) \
	  $(if $(FEATURES),--build-arg FEATURES=$(FEATURES),) .
	@echo "built $(IMAGE_REF)"

image-push: image ## Push the image to its registry
	$(DOCKER) push $(IMAGE_REF)

##@ Local cluster

# A locally built image has to be handed to the cluster somehow, and how depends
# on which cluster: kind and k3d import it, minikube loads it. Docker Desktop
# is two things depending on its age — the older kubeadm cluster shares this
# daemon's images, while the current one runs the node as a container of its
# own, and an image has to be pushed into that node's containerd. Which is
# which is decided by whether the node answers to `docker exec`.
#
# Anything else — a cluster that is not on this machine — has to pull the image
# from a registry, and `make load` refuses rather than pretending.
# Refuses to touch a cluster that is not obviously local. Every target that
# changes something depends on this.
local-only:
	@if [ -z "$(CONTEXT)" ]; then \
	  echo "kubectl has no current context, and CONTEXT was not set."; exit 1; \
	fi; \
	if [ "$(ALLOW_ANY_CONTEXT)" = "1" ]; then \
	  echo "WARNING: acting on '$(CONTEXT)' because ALLOW_ANY_CONTEXT=1"; \
	  exit 0; \
	fi; \
	for pattern in $(LOCAL_CONTEXTS); do \
	  case "$(CONTEXT)" in $${pattern//\%/*}) exit 0 ;; esac; \
	done; \
	echo "Refusing to act on kube context '$(CONTEXT)': it is not a local cluster."; \
	echo; \
	echo "This Makefile installs and deletes things, and runs a test that writes"; \
	echo "data. It only does that to a cluster on this machine — one of:"; \
	echo "  $(LOCAL_CONTEXTS)"; \
	echo; \
	echo "Switch context, or pass CONTEXT=<local cluster>."; \
	echo "If you genuinely mean this one: make <target> ALLOW_ANY_CONTEXT=1"; \
	exit 1

image-exists:
	@$(DOCKER) image inspect $(IMAGE_REF) >/dev/null 2>&1 || { \
	  echo "$(IMAGE_REF) has not been built. Run 'make image' first, or 'make dev' which does."; \
	  exit 1; \
	}

load: local-only image-exists ## Give the image to whatever cluster kubectl points at
	@context=$$($(KUBECTL) config current-context 2>/dev/null); \
	if [ -z "$$context" ]; then echo "kubectl has no current context"; exit 1; fi; \
	case "$$context" in \
	  kind-*) $(KIND) load docker-image $(IMAGE_REF) --name "$${context#kind-}" ;; \
	  k3d-*) k3d image import $(IMAGE_REF) --cluster "$${context#k3d-}" ;; \
	  minikube) minikube image load $(IMAGE_REF) ;; \
	  docker-desktop|rancher-desktop) \
	    node=$$($(KUBECTL) --context "$$context" get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
	    if [ -n "$$node" ] && $(DOCKER) exec "$$node" true >/dev/null 2>&1; then \
	      echo "importing $(IMAGE_REF) into $$node"; \
	      $(DOCKER) save $(IMAGE_REF) | $(DOCKER) exec -i "$$node" ctr -n k8s.io images import - >/dev/null; \
	      echo "imported"; \
	    else \
	      echo "$$context shares this Docker daemon; $(IMAGE_REF) is already visible to it"; \
	    fi ;; \
	  *) \
	    echo "Context '$$context' is not a local cluster this can hand an image to."; \
	    echo "Push it somewhere the cluster can pull from:"; \
	    echo "  make image-push IMAGE=registry.example.com/sightingdb TAG=$(TAG)"; \
	    exit 1 ;; \
	esac

kind-up: ## Create the local kind cluster if it is not already there
	@if $(KIND) get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER); then \
	  echo "kind cluster $(KIND_CLUSTER) is already up"; \
	else \
	  $(KIND) create cluster --name $(KIND_CLUSTER); \
	fi

kind-load: local-only image-exists ## Load the built image into the kind cluster named by KIND_CLUSTER
	$(KIND) load docker-image $(IMAGE_REF) --name $(KIND_CLUSTER)

kind-down: ## Delete the local kind cluster
	$(KIND) delete cluster --name $(KIND_CLUSTER)

##@ Chart

helm-lint: ## Lint the chart
	$(HELM) lint $(CHART)
	$(HELM) lint $(CHART) --values $(VALUES)

helm-template: ## Render the chart to stdout, as it would be installed
	@$(HELM) template $(RELEASE) $(CHART) --namespace $(NAMESPACE) \
	  --values $(VALUES) --set image.repository=$(IMAGE) --set image.tag=$(TAG) \
	  $(HELM_ARGS)

helm-package: ## Package the chart into a .tgz
	$(HELM) package $(CHART)

sync-version: ## Copy the crate version into the chart and the OpenAPI document
	@version=$$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2); \
	sed -i.bak "s/^appVersion: .*/appVersion: \"$$version\"/" $(CHART)/Chart.yaml; \
	rm -f $(CHART)/Chart.yaml.bak; \
	sed -i.bak "s/^  version: \".*\"/  version: \"$$version\"/" doc/openapi.yaml; \
	rm -f doc/openapi.yaml.bak; \
	echo "chart appVersion and the OpenAPI version are now $$version"

##@ Running it

install: local-only ## Install the release, or upgrade it if it is already there
	$(HELM_INSTALL)

upgrade: install ## The same thing; helm upgrade --install does both

uninstall: local-only ## Remove the release, leaving its volume behind
	$(HELM) uninstall $(RELEASE) --kube-context $(CONTEXT) --namespace $(NAMESPACE)

status: ## What the release is doing
	$(KUBE) get statefulset,pod,svc,pvc,job -l app.kubernetes.io/instance=$(RELEASE)

logs: ## Follow the daemon's logs
	$(KUBE) logs -f statefulset/$(RELEASE) --all-containers

port-forward: ## Forward the API to localhost (see PORT below) until interrupted
	@echo "http://localhost:$(PORT)/_management/  (key: make admin-key)"
	$(KUBE) port-forward svc/$(RELEASE) $(PORT):$(PORT)

admin-key: ## Print the admin API key the release was installed with
	@$(KUBE) get secret $(RELEASE)-acl -o jsonpath='{.data.admin-key}' | base64 -d; echo

acl: ## Print every key the release was installed with, and what each may reach
	@$(KUBE) get secret $(RELEASE)-acl -o jsonpath='{.data.acl\.toml}' | base64 -d
	@echo
	@echo "# Keys created in the management interface live on the volume, not here."

rotate-key: local-only ## Replace the admin key with a freshly generated one
	@echo "This forgets every key the release knows, including any made in the"
	@echo "management interface, and generates one new admin key."
	@printf "Continue? [y/N] "; read answer; [ "$$answer" = y ] || [ "$$answer" = Y ] || exit 1
	@echo "old key: $$($(KUBE) get secret $(RELEASE)-acl -o jsonpath='{.data.admin-key}' | base64 -d)"
	$(KUBE) delete secret $(RELEASE)-acl
	$(HELM_INSTALL) --set acl.overwriteOnStart=true
	@$(KUBE) rollout status statefulset/$(RELEASE) --timeout=300s
	@echo "new key: $$($(KUBE) get secret $(RELEASE)-acl -o jsonpath='{.data.admin-key}' | base64 -d)"
	@echo
	@echo "Put acl.overwriteOnStart back to its default with 'make install', or"
	@echo "keys made in the interface will be replaced at every restart."

chart-test: local-only ## Run the chart's own test: write a sighting and read it back
	$(HELM) test $(RELEASE) --kube-context $(CONTEXT) --namespace $(NAMESPACE) --logs

wait: ## Block until the pod is ready
	$(KUBE) rollout status statefulset/$(RELEASE) --timeout=300s

smoke: local-only ## Write and read a sighting, and export it as STIX, over a temporary port-forward
	@set -e; \
	$(KUBE) port-forward svc/$(RELEASE) $(PORT):$(PORT) >/dev/null 2>&1 & \
	forward=$$!; \
	trap "kill $$forward 2>/dev/null || true" EXIT; \
	key=$$($(KUBE) get secret $(RELEASE)-acl -o jsonpath='{.data.admin-key}' | base64 -d); \
	for i in $$(seq 1 30); do \
	  curl -fsSk "http://localhost:$(PORT)/health" >/dev/null 2>&1 && break; \
	  sleep 1; \
	done; \
	echo "health:  $$(curl -fsSk http://localhost:$(PORT)/health)"; \
	curl -fsSk -H "Authorization: $$key" "http://localhost:$(PORT)/w/smoke/test?val=127.0.0.1" >/dev/null; \
	echo "sighting: $$(curl -fsSk -H "Authorization: $$key" 'http://localhost:$(PORT)/r/smoke/test?val=127.0.0.1&noshadow')"; \
	echo "stix:     $$(curl -fsSk -X POST -H "Authorization: $$key" -H 'Content-Type: application/json' \
	  -d '{"namespace":"smoke/test"}' http://localhost:$(PORT)/_api/stix | head -c 120)..."

##@ Everything at once

refresh: image load install wait ## Rebuild, load and roll the pod: the loop while changing code
	@echo "$(RELEASE) is running the image you just built"

restart: local-only ## Restart the pod without changing the release
	$(KUBE) rollout restart statefulset/$(RELEASE)

deploy: image load install wait smoke ## Build and install into the cluster you already have
	@echo
	@echo "SightingDB is running in $$($(KUBECTL) config current-context)."
	@echo "  make port-forward   reach it at http://localhost:$(PORT)/_management/"
	@echo "  make admin-key      the API key to sign in with"

dev: image kind-up kind-load install wait smoke ## From nothing — makes a kind cluster of its own
	@echo
	@echo "SightingDB is running in kind cluster '$(KIND_CLUSTER)'."
	@echo "  make port-forward   reach it at http://localhost:$(PORT)/_management/"
	@echo "  make admin-key      the API key to sign in with"
	@echo "  make chart-test     run the chart's own test"
	@echo "  make teardown       delete the cluster and everything in it"

teardown: kind-down ## Delete the local cluster and everything in it

##@ Help

help: ## This list
	@printf "SightingDB — build it, and run it locally on Kubernetes.\n\n"
	@printf "  \033[1mmake dev\033[0m      image → a kind cluster of its own → chart → smoke test\n"
	@printf "  \033[1mmake deploy\033[0m   image → the cluster kubectl already points at → chart → smoke test\n"
	@awk 'BEGIN {FS = ":.*##"} \
	     /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
	     /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' \
	  $(MAKEFILE_LIST)
	@printf "\n\033[1mVariables\033[0m (override on the command line: make dev TAG=wip)\n"
	@printf "  %-15s %s\n" IMAGE "$(IMAGE)"
	@printf "  %-15s %s\n" TAG "$(TAG)"
	@printf "  %-15s %s\n" CONTEXT "$(CONTEXT)"
	@printf "  %-15s %s\n" NAMESPACE "$(NAMESPACE)"
	@printf "  %-15s %s\n" RELEASE "$(RELEASE)"
	@printf "  %-15s %s\n" KIND_CLUSTER "$(KIND_CLUSTER)"
	@printf "  %-15s %s\n" VALUES "$(VALUES)"
	@printf "  %-15s %s\n" PORT "$(PORT)"
	@printf "  %-15s %s\n" FEATURES "$(FEATURES)$(if $(FEATURES),, (empty: link OpenSSL dynamically))"
	@printf "  %-15s %s\n" HELM_ARGS "$(HELM_ARGS)$(if $(HELM_ARGS),, (empty: passed to helm upgrade --install))"
