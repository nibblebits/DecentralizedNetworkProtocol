SYSTEM_OBJECT_FILES = ./build/dnpexception.o ./build/system.o ./build/misc.o ./build/rsa.o ./build/network.o ./build/networkpacket.o ./build/dnpdatagrampacket.o ./build/activeippacket.o ./build/hellopacket.o ./build/hellorespondpacket.o ./build/pingpacket.o ./build/dnpfile.o ./build/threadpool.o ./build/dnpkernelclient.o ./build/dnplinuxkernelclient.o
OBJECT_FILE_FLAGS = -c -g -fPIC -std=c++14 
SYSTEM_LIB_LOCAL_FILENAME = libdnp.so
SYSTEM_LIB_FILE_LOCATION = ./bin/${SYSTEM_LIB_LOCAL_FILENAME}
INCLUDES = -I ./include -I ../kernel_mod/linux

install: all
	cp ${SYSTEM_LIB_FILE_LOCATION} /usr/lib/${SYSTEM_LIB_LOCAL_FILENAME}

all: ${SYSTEM_OBJECT_FILES}
	g++ ${SYSTEM_OBJECT_FILES} ${EXTERNAL_OBJECT_FILES} -g -o ${SYSTEM_LIB_FILE_LOCATION} -lstdc++fs -lpthread -lssl -lcrypto -lm -lrt -shared -Wl,-rpath,'./lib'-export-dynamic

./build/dnpexception.o: ./src/dnpexception.cpp
	g++ ${INCLUDES} ./src/dnpexception.cpp -o ./build/dnpexception.o ${OBJECT_FILE_FLAGS}

./build/system.o: ./src/system.cpp
	g++ ${INCLUDES} ./src/system.cpp -o ./build/system.o ${OBJECT_FILE_FLAGS}

./build/misc.o: ./src/misc.cpp
	g++ ${INCLUDES} ./src/misc.cpp -o ./build/misc.o ${OBJECT_FILE_FLAGS}

./build/rsa.o: ./src/crypto/rsa.cpp
	g++ ${INCLUDES} ./src/crypto/rsa.cpp -o ./build/rsa.o ${OBJECT_FILE_FLAGS}

./build/network.o: ./src/network.cpp
	g++ ${INCLUDES} ./src/network.cpp -o ./build/network.o ${OBJECT_FILE_FLAGS}

./build/networkpacket.o: ./src/network/networkpacket.cpp
	g++ ${INCLUDES} ./src/network/networkpacket.cpp -o ./build/networkpacket.o ${OBJECT_FILE_FLAGS}


./build/pingpacket.o: ./src/network/pingpacket.cpp
	g++ ${INCLUDES} ./src/network/pingpacket.cpp -o ./build/pingpacket.o ${OBJECT_FILE_FLAGS}

./build/hellopacket.o: ./src/network/hellopacket.cpp
	g++ ${INCLUDES} ./src/network/hellopacket.cpp -o ./build/hellopacket.o ${OBJECT_FILE_FLAGS}

./build/activeippacket.o: ./src/network/activeippacket.cpp
	g++ ${INCLUDES} ./src/network/activeippacket.cpp -o ./build/activeippacket.o ${OBJECT_FILE_FLAGS}

./build/hellorespondpacket.o: ./src/network/hellorespondpacket.cpp
	g++ ${INCLUDES} ./src/network/hellorespondpacket.cpp -o ./build/hellorespondpacket.o ${OBJECT_FILE_FLAGS}


./build/dnpdatagrampacket.o: ./src/network/dnpdatagrampacket.cpp
	g++ ${INCLUDES} ./src/network/dnpdatagrampacket.cpp -o ./build/dnpdatagrampacket.o ${OBJECT_FILE_FLAGS}


./build/dnpkernelclient.o: ./src/dnpkernelclient.cpp
	g++ ${INCLUDES} ./src/dnpkernelclient.cpp -o ./build/dnpkernelclient.o ${OBJECT_FILE_FLAGS}
./build/dnplinuxkernelclient.o: ./src/dnplinuxkernelclient.cpp
	g++ ${INCLUDES} ./src/dnplinuxkernelclient.cpp -o ./build/dnplinuxkernelclient.o ${OBJECT_FILE_FLAGS}

./build/dnpfile.o: ./src/dnpfile.cpp
	g++ ${INCLUDES} ./src/dnpfile.cpp -o ./build/dnpfile.o ${OBJECT_FILE_FLAGS}

./build/threadpool.o: ./src/threadpool.cpp
	g++ ${INCLUDES} ./src/threadpool.cpp -o ./build/threadpool.o ${OBJECT_FILE_FLAGS}

	
clean:
	rm -f ${SYSTEM_OBJECT_FILES}
