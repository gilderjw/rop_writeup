CC=gcc

all: level7

level7: level7.c
	$(CC) -o level7 -m32 -Wno-deprecated-declarations -Wno-overflow -fno-stack-protector level7.c

clean:
	rm level7
