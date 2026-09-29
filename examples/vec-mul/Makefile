NODES=helper node-1 node-2 node-3 node-4

.PHONY: docker run down certs build

docker: ## Build the example image (the node and the certificate generator)
	docker build --rm -t helium:vec-mul ../.. -f ./Dockerfile

run: docker ## Build and run the whole example: the certificates are generated first
	docker compose up --abort-on-container-exit

down: ## Tear down the example, including the generated certificates
	docker compose down --volumes

certs: ## Generate the certificates locally, for running the nodes outside of docker
	go run ../gencerts -out ./certs $(NODES)

build:
	go build -v .
