#ifndef DNPFILE_H
#define DNPFILE_H

#include <string>
#include <fstream>
#include "dnp.h"

namespace Dnp
{

    /**
     *  Dnp File format 
     * - file header
     * - data table header
     * - data table
     * - data scattered    
     */
    struct file_header
    {
        // Signature
        char signature[DNP_SIGNATURE_SIZE];
        // The version of this Dnp file
        DNP_FILE_FORMAT_VERSION version;
        // Total nodes available in the system 
        unsigned long total_nodes;
        // The absolute position of the first node
        NODE_POSITION first_node;
    };

    // Represents 
    struct data_table_header
    {
        // Total sectors that can be used by this data table
        unsigned int total_sectors;
    };

    struct node_header
    {
        NODE_ID id;
        unsigned long size;
        NODE_FLAGS flags;
        NODE_DATA_POSITION data_pos;
        NODE_POSITION next_node_pos;
    };


    class DnpFile
    {
        public:
            DnpFile();
            virtual ~DnpFile();
            void openFile(std::string filename);
            std::string getNodeFilename();
            void createNode(NODE_ID node_id, unsigned long size, const char* data);
            void loadNode(NODE_ID node_id);
        

        private:
            void createNodeTable();
            void loadFile(std::string filename);
            void setupFile(std::string filename);
            void initFileHeader(struct file_header* header);
            void initNodeHeader(struct node_header* header);

            /**
             * Returns a free position in the DnpFile where you can safely write the provided size
             * If there is no room then zero is returned.
             */
            unsigned long getFreePositionForData(unsigned long size);

            /**
             * Marks the data as non free in the data table
             */
             void markDataTaken(unsigned long pos, unsigned long size);
        protected:
            std::fstream node_file;
            std::string node_filename;
    };
};

#endif