ROOT ?= ../..
EMACS ?= emacs

CC	= gcc
LD	= gcc

CFLAGS	= -std=gnu99 -ggdb3 -Wall -fPIC

all: emacshark.so

%.so: %.o
	$(LD) -shared $(LDFLAGS) -o $@ $< -lpcap

%.o: %.c
	$(CC) $(CFLAGS) -I$(ROOT)/src -c $<
