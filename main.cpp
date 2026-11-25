// @author piercer
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static uint16_t u16(const std::vector<uint8_t>& b, size_t o) { return b[o] | (b[o + 1] << 8); }
static uint32_t u32(const std::vector<uint8_t>& b, size_t o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24); }

struct Sec { uint32_t va, vsize, ra, rsize; };

static size_t rva2off(uint32_t rva, const std::vector<Sec>& secs) {
    for (const auto& s : secs)
        if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rsize))
            return s.ra + (rva - s.va);
    return static_cast<size_t>(-1);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { std::cout << "Uso: piercer_dll_exports <arquivo.dll>\n"; return 1; }
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) return 1;
    std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    uint32_t lf = u32(b, 0x3C);
    uint16_t numSec = u16(b, lf + 6);
    uint16_t optSize = u16(b, lf + 20);
    size_t optOff = lf + 24;
    bool is64 = u16(b, optOff) == 0x20B;
    uint32_t expRva = u32(b, optOff + (is64 ? 112 : 96));
    std::vector<Sec> secs;
    for (uint16_t i = 0; i < numSec; ++i) {
        size_t o = optOff + optSize + i * 40;
        secs.push_back({ u32(b, o + 12), u32(b, o + 8), u32(b, o + 20), u32(b, o + 16) });
    }
    size_t expOff = rva2off(expRva, secs);
    if (expOff == static_cast<size_t>(-1)) { std::cout << "Sem Export Table.\n"; return 0; }
    uint32_t numNames = u32(b, expOff + 24);
    size_t namesOff = rva2off(u32(b, expOff + 32), secs);
    std::cout << "=== Exports (" << numNames << ") ===\n";
    for (uint32_t i = 0; i < numNames && namesOff + i * 4 + 4 <= b.size(); ++i) {
        size_t sOff = rva2off(u32(b, namesOff + i * 4), secs);
        if (sOff < b.size()) std::cout << "  " << reinterpret_cast<const char*>(&b[sOff]) << "\n";
    }
    return 0;
}
