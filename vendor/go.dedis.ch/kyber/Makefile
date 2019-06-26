all: test

gopath=$(shell go env GOPATH)
CODING = $(gopath)/src/github.com/dedis/Coding/bin

test_fmt:
	@echo Checking correct formatting of files
	@{ \
		files=$$( go fmt ./... ); \
		if [ -n "$$files" ]; then \
		echo "Files not properly formatted: $$files"; \
		exit 1; \
		fi; \
		if ! go vet ./...; then \
		exit 1; \
		fi \
	}

test_lint:
	@echo Checking linting of files
	@{ \
		go get -u github.com/golang/lint/golint; \
		lintfiles=$$( golint ./... | egrep -v _test.go ); \
		if [ -n "$$lintfiles" ]; then \
		echo "Lint errors:"; \
		echo "$$lintfiles"; \
		exit 1; \
		fi \
	}

test_goveralls:
	go get github.com/mattn/goveralls
	$(CODING)/coveralls.sh $(EXCLUDE_TEST)
	$(gopath)/bin/goveralls -coverprofile=profile.cov -service=travis-ci || true

test: test_fmt test_lint test_goveralls


