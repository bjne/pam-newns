CFLAGS = -c -fPIC -fno-stack-protector -Wall
LDFLAGS = --shared
LIBS = -lpam

all: pam_newns.so

clean:
	rm -f pam_newns.so pam_newns.o

pam_newns.o: src/pam_newns.c
	$(CC) $(CFLAGS) src/pam_newns.c

pam_newns.so: pam_newns.o
	$(LD) $(LDFLAGS) -o pam_newns.so pam_newns.o $(LIBS)
