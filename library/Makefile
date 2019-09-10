SYSTEM_OBJECT_FILES = ./build/system.o ./build/misc.o ./build/rsa.o ./build/network.o ./build/cell.o ./build/mmapcell.o ./build/dnpfile.o ./build/threadpool.o ./build/domainsocket.o ./build/clientdomainsocket.o ./build/serverdomainsocket.o ./build/serverclientdomainsocket.o
OBJECT_FILE_FLAGS = -c -g -fPIC -std=c++14 -g
SYSTEM_LIB_LOCAL_FILENAME = libdnp.so
SYSTEM_LIB_FILE_LOCATION = ./bin/${SYSTEM_LIB_LOCAL_FILENAME}
INCLUDES = ./include

install: all
	cp ${SYSTEM_LIB_FILE_LOCATION} /usr/lib/${SYSTEM_LIB_LOCAL_FILENAME}

all: ${SYSTEM_OBJECT_FILES}
	g++ ${SYSTEM_OBJECT_FILES} ${EXTERNAL_OBJECT_FILES} -g -o ${SYSTEM_LIB_FILE_LOCATION} -lstdc++fs -lpthread -lssl -lcrypto -lm -lrt -shared -Wl,-rpath,'./lib'-export-dynamic

./build/system.o: ./src/system.cpp
	g++ -I ${INCLUDES} ./src/system.cpp -o ./build/system.o ${OBJECT_FILE_FLAGS}

./build/misc.o: ./src/misc.cpp
	g++ -I ${INCLUDES} ./src/misc.cpp -o ./build/misc.o ${OBJECT_FILE_FLAGS}

./build/rsa.o: ./src/crypto/rsa.cpp
	g++ -I ${INCLUDES} ./src/crypto/rsa.cpp -o ./build/rsa.o ${OBJECT_FILE_FLAGS}

./build/network.o: ./src/network.cpp
	g++ -I ${INCLUDES} ./src/network.cpp -o ./build/network.o ${OBJECT_FILE_FLAGS}

./build/cell.o: ./src/cell.cpp
	g++ -I ${INCLUDES} ./src/cell.cpp -o ./build/cell.o ${OBJECT_FILE_FLAGS}
./build/mmapcell.o: ./src/mmapcell.cpp
	g++ -I ${INCLUDES} ./src/mmapcell.cpp -o ./build/mmapcell.o ${OBJECT_FILE_FLAGS}

./build/dnpfile.o: ./src/dnpfile.cpp
	g++ -I ${INCLUDES} ./src/dnpfile.cpp -o ./build/dnpfile.o ${OBJECT_FILE_FLAGS}

./build/threadpool.o: ./src/threadpool.cpp
	g++ -I ${INCLUDES} ./src/threadpool.cpp -o ./build/threadpool.o ${OBJECT_FILE_FLAGS}

./build/domainsocket.o: ./src/domainsocket.cpp
	g++ -I ${INCLUDES} ./src/domainsocket.cpp -o ./build/domainsocket.o ${OBJECT_FILE_FLAGS}
./build/clientdomainsocket.o: ./src/clientdomainsocket.cpp
	g++ -I ${INCLUDES} ./src/clientdomainsocket.cpp -o ./build/clientdomainsocket.o ${OBJECT_FILE_FLAGS}
./build/serverdomainsocket.o: ./src/serverdomainsocket.cpp
	g++ -I ${INCLUDES} ./src/serverdomainsocket.cpp -o ./build/serverdomainsocket.o ${OBJECT_FILE_FLAGS}
./build/serverclientdomainsocket.o: ./src/serverclientdomainsocket.cpp
	g++ -I ${INCLUDES} ./src/serverclientdomainsocket.cpp -o ./build/serverclientdomainsocket.o ${OBJECT_FILE_FLAGS}
	
clean:
	rm -f ${SYSTEM_OBJECT_FILES}
