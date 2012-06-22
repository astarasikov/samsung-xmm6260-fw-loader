APPNAME=modem-ctl
CC=$(CROSS_COMPILE)gcc
CFLAGS=-std=c99 -static -Wall

CFILES = modem-ctl.c io_helpers.c log.c
OBJFILES = $(patsubst %.c,%.o,$(CFILES))

all: $(APPNAME)

$(APPNAME): $(OBJFILES)
	$(CC) $(CFLAGS) -o $@ $(OBJFILES)

$(OBJFILES): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(APPNAME)
	rm -f *.o
