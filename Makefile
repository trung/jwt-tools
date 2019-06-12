GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
LD_FLAGS := -X main.Commit=${GIT_COMMIT} -X main.Version=${GIT_BRANCH} -s -w
XC_ARCH := amd64
XC_OS := linux darwin windows

.PHONY: docs

default: all

build:
	@echo Branch: ${GIT_BRANCH}
	@echo Commit: ${GIT_COMMIT}
	@gox \
		-os="${XC_OS}" \
		-arch="${XC_ARCH}" \
		-ldflags="${LD_FLAGS}" \
		-output "build/{{.OS}}_{{.Arch}}/jwt" \
		.
	@echo
	@echo Done!
	@ls build/*

all: tools clean docs build

clean:
	@rm -rf build/

docs:
	@rm -rf docs/jwt*.md
	@go run docs/gen.go

tools: gox
	@go mod download
	@echo "Build tools are ready"

gox:
ifeq (, $(shell which gox))
	@go get -u github.com/mitchellh/gox
endif