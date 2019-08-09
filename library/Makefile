SYSTEM_OBJECT_FILES = ./build/system.o ./build/network.o ./build/node.o ./build/dnpfile.o
OBJECT_FILE_FLAGS = -c -g -fPIC -std=c++14 -g
SYSTEM_LIB_LOCAL_FILENAME = libdnp.so
SYSTEM_LIB_FILE_LOCATION = ./bin/${SYSTEM_LIB_LOCAL_FILENAME}
INCLUDES = ./include

install: all
	cp ${SYSTEM_LIB_FILE_LOCATION} /usr/lib/${SYSTEM_LIB_LOCAL_FILENAME}

all: ${SYSTEM_OBJECT_FILES}
	g++ ${SYSTEM_OBJECT_FILES} ${EXTERNAL_OBJECT_FILES} -g -o ${SYSTEM_LIB_FILE_LOCATION} -lstdc++fs -lpthread -lm -lrt -shared -Wl,-rpath,'./lib'-export-dynamic

./build/system.o: ./src/system.cpp
	g++ -I ${INCLUDES} ./src/system.cpp -o ./build/system.o ${OBJECT_FILE_FLAGS}

./build/network.o: ./src/network.cpp
	g++ -I ${INCLUDES} ./src/network.cpp -o ./build/network.o ${OBJECT_FILE_FLAGS}

./build/node.o: ./src/node.cpp
	g++ -I ${INCLUDES} ./src/node.cpp -o ./build/node.o ${OBJECT_FILE_FLAGS}


./build/dnpfile.o: ./src/dnpfile.cpp
	g++ -I ${INCLUDES} ./src/dnpfile.cpp -o ./build/dnpfile.o ${OBJECT_FILE_FLAGS}


clean:
	rm -f ${SYSTEM_OBJECT_FILES}
