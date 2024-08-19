build:
	CGO_ENABLED=1 go build -ldflags="-extldflags=-static" -o sherlock main.go

clean:
	rm -f *.bin *.json
	rm sherlock

run:
	sudo ./sherlock
