SYSTEM_OBJECT_FILES = 
OBJECT_FILE_FLAGS = -c -g -fPIC -std=c++14 -g
EXE_LOCATION = ./bin/dnp
INCLUDES = -I ./include -I../library/include

all: ${SYSTEM_OBJECT_FILES}
	g++ -g ${INCLUDES} ./src/main.cpp -ldnp -ldl -g -std=c++14 -o ${EXE_LOCATION};

clean:
	rm -f ${SYSTEM_OBJECT_FILES}
