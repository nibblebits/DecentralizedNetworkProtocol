SYSTEM_OBJECT_FILES = 
OBJECT_FILE_FLAGS = -c -g -fPIC -std=c++14 -g
EXE_LOCATION = ./bin/test
INCLUDES = -I ./include -I../library/include

all: ${SYSTEM_OBJECT_FILES}
	g++ -g ${INCLUDES} ./src/main.cpp -ldnp -ldl -std=c++14 -o ${EXE_LOCATION};

clean:
	rm -f ${SYSTEM_OBJECT_FILES}
