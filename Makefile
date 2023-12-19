SRCS :=		filedataLogger.c fileScan.c debug.c

LIBSURICATA_CONFIG ?= libsuricata-config

CPPFLAGS +=	`$(LIBSURICATA_CONFIG) --cflags`
CPPFLAGS +=	-DSURICATA_PLUGIN -I.
CPPFLAGS +=	"-D__SCFILENAME__=\"$(*F)\""

OBJS :=		$(SRCS:.c=.o)

LIBAMCLIENT = amclient
LIBAMCLIENT_DIR = lib
LIBAMCLIENT_PATH = lib/lib$(LIBAMCLIENT).a

inspectorPlugin.so: $(OBJS)
	$(CC) -fPIC -shared -o $@ $(OBJS) -L$(LIBAMCLIENT_DIR) -l$(LIBAMCLIENT)

%.o: %.c
	$(CC) -fPIC $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.so *~
