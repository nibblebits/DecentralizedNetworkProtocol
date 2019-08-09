#ifndef FLAGS_H
#define FLAGS_H

enum
{
    // We hold the raw node data locally 
    NODE_FLAG_DATA_LOCAL = 0b00000001,
    // We are aware of the node but we don't hold the data fetch it from the network
    NODE_FLAG_DATA_EXTERNAL = 0b00000010
};

#endif