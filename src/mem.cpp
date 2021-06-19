#include "mem.h"
#include <map>
#include "errors.h"


// initialize this to some illegal value (not 0, not a small integer).
// not static (other files will want to access this)
uint32_t mainImgId = 999999;

#define HEAP_REG_ID 1000 // let's just hope the program doesn't load more than 1000 shared libraries
// maps start address -> region
static std::map<uint64_t, ImgRegion*> imgRegions;

// counts the number of reads at each memory address
static std::map<uint64_t, uint32_t> memReadCount;

// the argument passed to the last call to malloc(), calloc() or realloc()
static uint64_t lastMallocSize;
static uint64_t lastCallocSize;
static uint64_t lastReallocSize;

void increaseReadCount(uint64_t addr, uint64_t size)
{
    for (uint64_t i = 0; i < size; i++) {
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
            fprintf(file, "0x%lx: [%u] 0x%x\n", addr, count, *((uint8_t*)addr));
            prevBigRead = addr;
        }
    }
}

std::vector<uint64_t> searchBytes(uint8_t* bytes, uint64_t n, const std::vector<ImgRegion*>& regions)
{
    std::vector<uint64_t> res;
    for (ImgRegion* reg : regions) {
        //printf("searching in 0x%lx -> 0x%lx\n", reg->startAddr, reg->endAddr);
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
    uint8_t bytes[] = {
        0x64, 0x03, 0x65, 0x03
    };
    std::vector<ImgRegion*> searchRegions;
    for (auto it = imgRegions.begin(); it != imgRegions.end(); it++) {
        ImgRegion* reg = it->second;
        if (reg->imgId == mainImgId || reg->imgId == HEAP_REG_ID) {
            searchRegions.push_back(reg);
        }
    }
    auto positions = searchBytes(bytes, sizeof(bytes), searchRegions);
    for (uint64_t pos : positions) {
        printf("pos=0x%lx -> ", pos);
        for (uint64_t i = 0; i < 8; i++) {
            printf("%x ", *(uint8_t*)(pos + i));
        }
        printf("\n");
    }
    if (positions.size() == 0) {
        printf("didn't find a position\n");
    }
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

void mallocBefore(ADDRINT size)
{
    lastMallocSize = size;
}

void mallocAfter(ADDRINT addr)
{
    ImgRegion* reg = new ImgRegion();
    reg->startAddr = addr;
    reg->endAddr = addr + lastMallocSize - 1;
    reg->imgId = HEAP_REG_ID;
    addImgRegion(reg);
}

void callocBefore(ADDRINT n, ADDRINT size)
{
    lastCallocSize = n * size;
}

void callocAfter(ADDRINT addr)
{
    ImgRegion* reg = new ImgRegion();
    reg->startAddr = addr;
    reg->endAddr = addr + lastCallocSize - 1;
    reg->imgId = HEAP_REG_ID;
    addImgRegion(reg);
}

void reallocBefore(ADDRINT addr, ADDRINT size)
{
    if (addr != 0) {
        auto it = imgRegions.find(addr);
        if (it != imgRegions.end()) {
            imgRegions.erase(it);
        }
        else {
            printf("catched invalid call to realloc(0x%lx, ...)\n", addr);
        }
    }
    lastReallocSize = size;
}

void reallocAfter(ADDRINT addr)
{
    ImgRegion* reg = new ImgRegion();
    reg->startAddr = addr;
    reg->endAddr = addr + lastReallocSize - 1;
    reg->imgId = HEAP_REG_ID;
    addImgRegion(reg);
}

void freeBefore(ADDRINT addr)
{
    // free(0) is a nop
    if (addr != 0) {
        auto it = imgRegions.find(addr);
        if (it != imgRegions.end()) {
            imgRegions.erase(it);
        }
        else {
            printf("catched invalid call to free(0x%lx)\n", addr);
        }
    }
}

void imgMemCallback(IMG img, void *v)
{
    //  Find malloc()
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)mallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)mallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, 
                       IARG_END);
        RTN_Close(mallocRtn);
    }
    //  Find calloc()
    RTN callocRtn = RTN_FindByName(img, "calloc");
    if (RTN_Valid(callocRtn))
    {
        RTN_Open(callocRtn);
        RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)callocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)callocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, 
                       IARG_END);
        RTN_Close(callocRtn);
    }
    //  Find realloc()
    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
        RTN_Open(reallocRtn);
        RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)reallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)reallocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, 
                       IARG_END);
        RTN_Close(reallocRtn);
    }
    // Find free()
    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)freeBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
    }
}
