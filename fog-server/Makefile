GOBUILDFLAGS =

./fog-server: ./fog-server.go ./stack.go ./config.go
	go build $(GOBUILDFLAGS) -o "$@" $^

test:
	go test -v

clean:
	rm -f ./fog-server

.PHONY: test clean
