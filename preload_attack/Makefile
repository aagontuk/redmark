APPS = victim victim_malloc attacker malmalloc.so

LDFLAGS =  -libverbs -lpthread
CFLAGS += -Wall -Wextra
CXXFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: CXXFLAGS += -O2
all: ${APPS}
 
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

victim: victim.cpp
	g++ victim.cpp $(CXXFLAGS) $(LDFLAGS) -lrdmacm -L./ -o victim

attacker: attacker.cpp
	g++ attacker.cpp $(CXXFLAGS) $(LDFLAGS) -lrdmacm   -o attacker

malmalloc.so: CFLAGS += -fPIC -shared
malmalloc.so: malmalloc.c
	gcc $(CFLAGS) $< -o $@ -ldl -lrdmacm -libverbs

victim_malloc: victim_malloc.c
	gcc $(CFLAGS) $< -o $@

debug: CFLAGS += -DDEBUG -g -O0
debug: CXXFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: clean
