APPS = victim attacker victim_odp

LDFLAGS =  -libverbs -lpthread #-ldl
CFLAGS += -Wall -std=c++11 -I./  

all: CFLAGS += -O2
all: ${APPS}
 
clean:
	$(foreach fname,${APPS}, rm -f ${fname})

victim: victim.cpp
	g++ victim.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm -L./ -o victim

victim_odp: victim_odp.cpp
	g++ victim_odp.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm -L./ -o victim_odp


attacker: attacker.cpp
	g++ attacker.cpp $(CFLAGS) $(LDFLAGS) -lrdmacm   -o attacker


debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: clean
