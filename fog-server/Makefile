GOBUILDFLAGS =

./fog-server: ./fog-server.go ./stack.go
	go build $(GOBUILDFLAGS) -o "$@" $^

test:
	go test -v

clean:
	rm -f ./fog-server

.PHONY: test clean
