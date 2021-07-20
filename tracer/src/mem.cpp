#include "mem.h"
#include <map>
#include "errors.h"
#include <set>

// maps start address -> region
static std::map<uint64_t, ImgRegion*> imgRegions;
// the ids of the regions used by the python interpreter
static std::set<uint32_t> pythonImgIds;


void addImgRegion(ImgRegion* reg)
{
    imgRegions[reg->startAddr] = reg;
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

void markPythonImg(uint32_t id)
{
    pythonImgIds.insert(id);
}

bool isInPythonRegion(uint64_t addr)
{
    return pythonImgIds.find(getImgId(addr)) != pythonImgIds.end();
}
