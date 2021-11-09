
# Engine and Bundle build information
#DEBUG := 1
# app name
DPI_APP = dpdk_integration

# list of source files
SRC +=  \
        main.c \
        customize.c

# DPDK variables
ifeq ($(RTE_SDK),)
     $(error "Please define RTE_SDK environment variable")
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc
# DPDK CFLAGS
CFLAGS  += -I$(RTE_SDK)/$(RTE_TARGET)/include -mssse3
#CFLAGS  += -I$(RTE_SDK)/$(RTE_TARGET)/include
CFLAGS  += -I$(PWD)/../src/include
# DPDK LDFLAGS
LDFLAGS += "-L$(RTE_SDK)/$(RTE_TARGET)/lib"
include $(RTE_SDK)/$(RTE_TARGET)/.config
include dpdk.mk
LDFLAGS += $(DPDK_LDLIBS-y)

# Other LDFLAGS
LDFLAGS += -ldl

# specific LDFLAGS for the application
LDFLAGS_EXTRA_LIBS = -lpcap -ljson-c  -ljson-c -lm -lpthread

LDFLAGS_FPIC = $(shell $(CC) -v 2>&1 | grep -q -e '--enable-default-pie' && echo -no-pie)

LIBNDPI = $(PWD)/../src/lib/libndpi.a
STATIC_LDFLAGS_LIBS = $(LDFLAGS_FPIC) -Wl,--whole-archive -Wl,--start-group  \
	$(LIBNDPI) \
        -Wl,--end-group -Wl,--no-whole-archive

DYNAMIC_LDFLAGS_LIBS = -Wl,--whole-archive -Wl,--start-group -L ../src/lib   \
        -lndpi \
        -Wl,--end-group -Wl,--no-whole-archive

ifeq ($(STATIC),1)
LDFLAGS_LIBS = $(STATIC_LDFLAGS_LIBS)
else
LDFLAGS_LIBS = $(DYNAMIC_LDFLAGS_LIBS)
endif

# please set CROSS='' for native build
CROSS ?= 
# define default compiler
CC     = $(CROSS)gcc
AR     = $(CROSS)ar
RANLIB = $(CROSS)ranlib
LD     = $(CROSS)ld

CFLAGS_WARNING += -Wall -Wextra -Wstrict-prototypes -Werror 
CFLAGS_WARNING +=-Wno-stringop-overflow  -Wno-address-of-packed-member

CFLAGS_DEFINES += -D_GNU_SOURCE
CFLAGS_INCLUDE += -I$(DPI_SDK)/include -I$(DPI_SDK)/src/include

ifeq ($(DEBUG),1)
CFLAGS_OPT += -O0 -g
else
CFLAGS_OPT += -O2
endif

# create final flags 
CFLAGS  += $(CFLAGS_ARCH) $(CFLAGS_DEFINES) $(CFLAGS_WARNING) $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_EXTRA)
LDFLAGS += $(CFLAGS_ARCH) $(LDFLAGS_USER) $(LDFLAGS_LIBS) $(LDFLAGS_EXTRA_LIBS)

# application targets

OBJS = $(SRC:.c=.o) 
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(DPI_APP):  $(OBJS)
	$(CC) $(OBJS) -Wl,--no-as-needed $(LDFLAGS) -o $@ $(LDFLAGS_FOOTER)

INSTALLDIR ?= $(DPI_SDK)/src/bin

install: $(DPI_APP) 
	mkdir -p $(INSTALLDIR)
	cp $(DPI_APP) $(INSTALLDIR)/$(DPI_APP)

clean:
	$(RM) $(DPI_APP) $(OBJS)

.PHONY: clean install

.DEFAULT_GOAL := $(DPI_APP)


