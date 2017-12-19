CC=gcc

all: vuln

vuln: vuln.c
	$(CC) -o vuln -m32 -fno-stack-protector vuln.c

clean:
	rm vuln
