GOBUILDFLAGS =

obfs-flash-server: obfs-flash-server.go stack.go
	go build $(GOBUILDFLAGS) -o "$@" $^

test:
	go test -v

clean:
	rm -f obfs-flash-server

.PHONY: test clean
