CC ?= ${CROSS_COMPILE}gcc
LD ?= ${CROSS_COMPILE}ld
AR ?= ${CROSS_COMPILE}ar
NM ?= ${CROSS_COMPILE}nm
OBJCOPY ?= ${CROSS_COMPILE}objcopy
OBJDUMP ?= ${CROSS_COMPILE}objdump
READELF ?= ${CROSS_COMPILE}readelf

OBJS = main.o

CFLAGS += -Wall -I./
CFLAGS += -I${TEEC_EXPORT}/include
LDADD += $(LDFLAGS) -lteec -L${TEEC_EXPORT}

BINARY = pkcs11-se050-import

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
