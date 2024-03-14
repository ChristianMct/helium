GOCMD=go
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet

REQS = $(GOCMD) goimports staticcheck

.PHONY: check_tools
check_reqs:
	@$(foreach exec,$(REQS),\
		$(if $(shell which $(exec)),true,$(error "$(exec) not found in PATH.")))

ARTIFACTS_PATH=out
EXPORT_RESULT?=false # for CI please set EXPORT_RESULT to true

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all test

all: lint test

## Test:
test: ## Run the tests of the project
	$(GOTEST) ./...

fmt: # Run go fmt
	@FMTOUT=$$(go fmt ./...); \
	if [ -z $$FMTOUT ]; then\
        echo "go fmt: OK";\
	else \
		echo "go fmt: problems in files:";\
		echo $$FMTOUT;\
		false;\
    fi

vet: # Run go vet
	@if GOVETOUT=$$(go vet ./... 2>&1); then\
        echo "go vet: OK";\
	else \
		echo "go vet: problems in files:";\
		echo "$$GOVETOUT";\
		false;\
    fi

staticcheck: # Run staticcheck
	@STATICCHECKOUT=$$(staticcheck -go 1.20 -checks all ./...); \
	if [ -z "$$STATICCHECKOUT" ]; then\
        echo "staticcheck: OK";\
	else \
		echo "staticcheck: problems in files:";\
		echo "$$STATICCHECKOUT";\
		false;\
    fi
	
	@echo Checking all local changes are committed
	go mod tidy
	out=`git status --porcelain`; echo "$$out"; [ -z "$$out" ]

lint: check_reqs fmt vet staticcheck ## Run all the linters

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