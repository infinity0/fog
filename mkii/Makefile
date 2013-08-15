GOBUILDFLAGS =

obfs-flash-server: obfs-flash-server.go
	go build $(GOBUILDFLAGS) -o "$@" $^

clean:
	rm -f obfs-flash-server

.PHONY: clean
