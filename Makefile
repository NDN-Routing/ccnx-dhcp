CC = gcc
LD = gcc -pipe

BDECFLAGS=      -W -Wall -ansi -pedantic -Wbad-function-cast -Wcast-align \
                -Wcast-qual -Wchar-subscripts -Winline \
                -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
                -Wredundant-decls -Wshadow -Wstrict-prototypes -Wwrite-strings \
                -std=c99 -Wextra

#STRIP=touch
#CFLAGS = -pipe -g3
#CFLAGS += $(BDECFLAGS)

STRIP=strip
CFLAGS = -pipe

CCNX_DIR = ~/ccnx
INCLUDES = -I $(CCNX_DIR)/include
LIBS = $(CCNX_DIR)/lib/libccn.a -lcrypto

SRCS_DHCP = ccndhcpnode.c
PROG_DHCP = ccndhcpnode

OBJS_DHCP = ${SRCS_DHCP:.c=.o}

all: $(PROG_DHCP)

$(PROG_DHCP): $(OBJS_DHCP)
	$(LD) -o $@ $(OBJS_DHCP) $(LIBS)
	$(STRIP) $(PROG_DHCP)

rmtmp:
	$(RM) *.o

clean: rmtmp
	$(RM) $(PROG_DHCP)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

.PHONY: all rmtmp clean
