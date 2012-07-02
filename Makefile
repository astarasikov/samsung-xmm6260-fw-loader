APPNAME=modem-ctl
CC=$(CROSS_COMPILE)gcc
CFLAGS=-std=c99 -DDEBUG -static -Wall

CFILES = \
	fwloader_i9100.c \
	fwloader_i9250.c \
	io_helpers.c \
	log.c \
	modem-ctl.c \
	modemctl_common.c

OBJFILES = $(patsubst %.c,%.o,$(CFILES))

all: $(APPNAME)

$(APPNAME): $(OBJFILES)
	$(CC) $(CFLAGS) -o $@ $(OBJFILES)

$(OBJFILES): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(APPNAME)
	rm -f *.o
