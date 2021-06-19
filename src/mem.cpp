#include "mem.h"



// initialize this to some illegal value (not 0, not a small integer).
// not static (other files will want to access this)
uint32_t mainImgId = 999999;

#define HEAP_REGION     1000 // let's just hope the program doesn't load more than 1000 shared libraries
// maps start address -> region
static std::map<uint64_t, ImgRegion*> imgRegions;

// counts the number of reads at each memory address
static std::map<uint64_t, uint32_t> memReadCount;

void recordMemoryRead(ADDRINT addr, UINT32 size, void* v)
{
    for (uint32_t i = 0; i < size; i++) {
        memReadCount[addr + i]++;
    }
}

void addImgRegion(ImgRegion* reg)
{
    imgRegions[reg->startAddr] = reg;
}

void dumpMemReads(FILE* file)
{
    // print areas of memory we accessed a lot 
    uint32_t memThreshold = 5000;
    
    uint64_t prevBigRead = 0;
    for (auto it = memReadCount.begin(); it != memReadCount.end(); it++) {
        uint64_t addr = it->first;
        uint32_t count = it->second;
        if (count >= memThreshold) {
            if (addr != prevBigRead + 1) {
                fprintf(file, "\n");
            }
            fprintf(file, "0x%lx: [%u] %x\n", addr, count, *(uint8_t*)addr);
            prevBigRead = addr;
        }
    }
}

std::vector<uint64_t> searchBytes(uint8_t* bytes, uint64_t n, const std::vector<ImgRegion*>& regions)
{
    std::vector<uint64_t> res;
    for (ImgRegion* reg : regions) {
        printf("searching in 0x%lx -> 0x%lx\n", reg->startAddr, reg->endAddr);
        for (uint64_t addr = reg->startAddr; addr+n-1 <= reg->endAddr; addr++) {
            if (!memcmp(bytes, (uint8_t*)addr, n)) {
                res.push_back(addr);
            }
        }
    }
    return res;
}

void searchForPyOpcodes()
{
    /*uint8_t bytes[] = {
        0x65, 0x64, 0x64
    };
    std::vector<ImgRegion*> mainImgRegions;
    for (auto it =  imgRegions) {
        if (reg->imgId == mainImgId) {
            mainImgRegions.push_back(reg);
        }
    }
    auto positions = searchBytes(bytes, sizeof(bytes), mainImgRegions);
    for (uint64_t pos : positions) {
        printf("pos=0x%lx -> ", pos);
        for (uint64_t i = 0; i < 8; i++) {
            printf("%x ", *(uint8_t*)(pos + i));
        }
        printf("\n");
    }
    if (positions.size() == 0) {
        printf("didn't find a position\n");
    }*/
}


// returns 0 for an unknown image ID
uint32_t getImgId(uint64_t addr)
{
    for (auto it = imgRegions.begin(); it != imgRegions.end(); it++) {
        ImgRegion* reg = it->second;
        if (reg->startAddr <= addr && addr <= reg->endAddr) {
            return reg->imgId;
        }
    }
    return 0;
}


/*void imgMemCallback(IMG img, void *v)
{
    //  Find malloc()
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                       IARG_ADDRINT, "malloc",
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(mallocRtn);
    }

    // Find the free() function.
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
                       IARG_ADDRINT, FREE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}*/
