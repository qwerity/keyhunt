#include <util/secp256k1.h>
#include <cuda/secp256k1_v2/secp256k1_defines.cuh>

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>

using namespace secp256k1;

// Convert uint256 to secp256k1_fe_storage
static void convertUint256ToFeStorage(const uint256& src, secp256k1_fe_storage& dst)
{
    for (int i = 0; i < 8; ++i)
    {
        dst.n[i] = src.v[i];
    }
}

// Convert ecpoint to secp256k1_ge_storage
static void convertEcpointToGeStorage(const ecpoint& src, secp256k1_ge_storage& dst)
{
    convertUint256ToFeStorage(src.x, dst.x);
    convertUint256ToFeStorage(src.y, dst.y);
}

// Generate gTable
static std::vector<secp256k1_ge_storage> generateGTable()
{
    constexpr uint32_t tableSize = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G;
    std::vector<secp256k1_ge_storage> h_gTable(tableSize);
    
    ecpoint basePoint = G();
    
    std::cout << "Generating gTable..." << std::endl;
    std::cout << "Table size: " << tableSize << " entries" << std::endl;
    std::cout << "Chunks: " << ECMULT_GEN_PREC_N << std::endl;
    std::cout << "Values per chunk: " << ECMULT_GEN_PREC_G << std::endl;
    
    for (uint32_t chunk = 0; chunk < ECMULT_GEN_PREC_N; ++chunk)
    {
        if (chunk % 2 == 0)
        {
            std::cout << "Processing chunk " << chunk << "/" << ECMULT_GEN_PREC_N << std::endl;
        }
        
        ecpoint chunkBasePoint = basePoint;
        
        // Double the base point (chunk * ECMULT_GEN_PREC_B) times
        for (uint32_t i = 0; i < chunk * ECMULT_GEN_PREC_B; ++i)
        {
            chunkBasePoint = doublePoint(chunkBasePoint);
        }
        
        ecpoint currentPoint = chunkBasePoint;
        const uint32_t chunkOffset = chunk * ECMULT_GEN_PREC_G;
        
        // Store the first point (index 0)
        convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + 0]);
        
        // Generate and store the remaining points for this chunk
        for (uint32_t k = 2; k <= ECMULT_GEN_PREC_G; ++k)
        {
            currentPoint = addPoints(currentPoint, chunkBasePoint);
            convertEcpointToGeStorage(currentPoint, h_gTable[chunkOffset + (k - 1)]);
        }
    }
    
    std::cout << "gTable generation completed!" << std::endl;
    return h_gTable;
}

// Save gTable to binary file
static bool saveGTableToFile(const std::vector<secp256k1_ge_storage>& gTable, const std::string& filename)
{
    std::ofstream file(filename, std::ios::binary | std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Error: Cannot open file " << filename << " for writing" << std::endl;
        return false;
    }
    
    // Write the table data
    file.write(reinterpret_cast<const char*>(gTable.data()), 
               gTable.size() * sizeof(secp256k1_ge_storage));
    
    if (!file.good())
    {
        std::cerr << "Error: Failed to write data to file" << std::endl;
        file.close();
        return false;
    }
    
    file.close();
    return true;
}

// Calculate file size in human-readable format
static std::string formatFileSize(size_t bytes)
{
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unitIndex < 4)
    {
        size /= 1024.0;
        unitIndex++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
    return oss.str();
}

int main(int argc, char* argv[])
{
    const std::string defaultFilename = "gtables.bin";
    std::string outputFilename = defaultFilename;
    
    if (argc > 1)
    {
        outputFilename = argv[1];
    }
    
    std::cout << "=== gTable Generator ===" << std::endl;
    std::cout << "Output file: " << outputFilename << std::endl;
    std::cout << std::endl;
    
    // Generate the table
    auto gTable = generateGTable();
    
    // Calculate expected file size
    const size_t entrySize = sizeof(secp256k1_ge_storage);
    const size_t totalSize = gTable.size() * entrySize;
    
    std::cout << std::endl;
    std::cout << "Table statistics:" << std::endl;
    std::cout << "  Entries: " << std::setw(20) << std::right << gTable.size() << std::endl;
    std::cout << "  Entry size: " << std::setw(20) << std::right << entrySize << " bytes" << std::endl;
    std::cout << "  Total size: " << std::setw(20) << std::right << totalSize << " bytes" << std::endl;
    std::cout << "  Total size: " << std::setw(20) << std::right << formatFileSize(totalSize) << std::endl;
    std::cout << std::endl;
    
    // Save to file
    std::cout << "Saving gTable to file..." << std::endl;
    if (saveGTableToFile(gTable, outputFilename))
    {
        std::cout << "Successfully saved gTable to " << outputFilename << std::endl;
        std::cout << "File size: " << formatFileSize(totalSize) << std::endl;
        return 0;
    }
    else
    {
        std::cerr << "Failed to save gTable to file" << std::endl;
        return 1;
    }
}
