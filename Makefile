CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11 -Iinclude -D_POSIX_C_SOURCE=200809L
SRC = src/tap.c src/arp.c src/ipv4.c src/icmp.c src/udp.c src/tcp.c src/main.c
OBJ = $(SRC:.c=.o)
TARGET = netstack

.PHONY: all clean asan debug

all: CFLAGS += -O2
all: $(TARGET)

asan: CFLAGS += -fsanitize=address,undefined -g3 -O1 -fno-omit-frame-pointer
asan: clean $(TARGET)

debug: CFLAGS += -g3 -O0
debug: clean $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
