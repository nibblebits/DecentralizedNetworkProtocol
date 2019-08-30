#ifndef FLAGS_H
#define FLAGS_H

enum
{
    // We hold the raw node data locally 
    CELL_FLAG_DATA_LOCAL = 0b00000001,
    // We are aware of the node but we don't hold the data fetch it from the network
    CELL_FLAG_DATA_EXTERNAL = 0b00000010,
    // This flag is set if the cell has never been published to the network and should be published when next possible
    CELL_FLAG_NOT_PUBLISHED = 0b00000100
};

#endif