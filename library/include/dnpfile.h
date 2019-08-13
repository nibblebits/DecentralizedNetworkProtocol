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
        unsigned long total_cells;
        // The absolute position of the first node
        CELL_POSITION first_cell;

        // The absolute position of the most recently created node
        CELL_POSITION last_cell;

    };

    // Represents 
    struct data_table_header
    {
        // Total sectors that can be used by this data table
        unsigned int total_sectors;
    };

    struct cell_header
    {
        CELL_ID id;
        unsigned long size;
        CELL_FLAGS flags;
        CELL_DATA_POSITION data_pos;
        CELL_POSITION prev_cell_pos;
        CELL_POSITION next_cell_pos;
    };


    class DnpFile
    {
        public:
            DnpFile();
            virtual ~DnpFile();
            void openFile(std::string filename);
            std::string getNodeFilename();
            void createCell(CELL_ID cell_id, unsigned long size, const char* data);
            bool loadCell(CELL_ID cell_id, struct cell_header* cell_header, char** data);
        
        private:
            void createCellTable();
            void loadFile(std::string filename);
            void setupFile(std::string filename);
            void initFileHeader(struct file_header* header);
            void initCellHeader(struct cell_header* header);


            /**
             * Writes the current file header in memory to disk
             */
            void writeFileHeader();

            /**
             * Returns a free position in the DnpFile where you can safely write the provided size
             * If there is no room then zero is returned.
             */
            unsigned long getFreePositionForData(unsigned long size);
             /**
             * Returns a free position in the DnpFile where you can safely write the provided size
             * If there is no room then an exception is thrown
             */
            unsigned long getFreePositionForDataOrThrow(unsigned long size);

    
            /**
             * Marks the data as non free in the data table
             */
             void markDataTaken(unsigned long pos, unsigned long size);
        protected:
            std::fstream node_file;
            std::string node_filename;
            struct file_header loaded_file_header;
    };
};

#endif