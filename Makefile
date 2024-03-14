GOCMD=go
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet

ARTIFACTS_PATH=out
EXPORT_RESULT?=false # for CI please set EXPORT_RESULT to true

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all test

all: help

## Test:
test: ## Run the tests of the project
ifeq ($(EXPORT_RESULT), true)
	mkdir -p "${ARTIFACTS_PATH}"
	GO111MODULE=off go get -u github.com/jstemmer/go-junit-report
	$(eval OUTPUT_OPTIONS = | tee /dev/tty | go-junit-report -set-exit-code > "${ARTIFACTS_PATH}/junit-report.xml")
endif
	$(GOTEST) ./pkg/... $(OUTPUT_OPTIONS)

coverage: ## Run the tests of the project and export the coverage
	$(GOTEST) -cover -covermode=count -coverprofile="${ARTIFACTS_PATH}/profile.cov" ./pkg/... || true
	$(GOCMD) tool cover -func "${ARTIFACTS_PATH}/profile.cov"
ifeq ($(EXPORT_RESULT), true)
	mkdir -p "${ARTIFACTS_PATH}"
	GO111MODULE=off go get -u github.com/AlekSi/gocov-xml
	GO111MODULE=off go get -u github.com/axw/gocov/gocov
	gocov convert "${ARTIFACTS_PATH}/profile.cov" | gocov-xml > "${ARTIFACTS_PATH}/coverage.xml"
endif

## Lint:
lint: lint-go vet ## Run all available linters

lint-go: ## lint go files
	# Coding style static check.
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.2
	@go mod tidy
	golangci-lint run || true
	@echo "${YELLOW}WARN${RESET}  this test never fails - please check the log for actual issues"


vet: ## Check for suspicious constructs
	go vet ./pkg/...

## Protocol Buffers
gen-proto: ## Compile protobuf files
	protoc --go_out=./pkg/transport/api --go_opt=paths=source_relative --go-grpc_out=./pkg/transport/api \
		--go-grpc_opt=paths=source_relative --proto_path=./pkg/transport ./pkg/transport/*.proto


## Help:
help: ## Show this help.
	@echo 'Helium'
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)