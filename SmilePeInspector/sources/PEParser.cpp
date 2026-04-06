#include "PEParser.h" // rutas directas
#include "Entropy.h"
#include <fstream>
#include <algorithm>

PEInfo AnalyzePE(const std::string& filePath) {
    PEInfo info = { false, false, 0.0, {}, {} };

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) return info;

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // mapear archivo a memoria
    std::vector<uint8_t> fullData(fileSize);
    file.read(reinterpret_cast<char*>(fullData.data()), fileSize);

    info.globalEntropy = CalculateEntropy(fullData);

    // validar estructura minima
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return info;

    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fullData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return info; // no tiene 'MZ'

    if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew >= fileSize - sizeof(IMAGE_NT_HEADERS32)) return info;

    // validar firma pe causaaaa
    DWORD* signature = reinterpret_cast<DWORD*>(fullData.data() + dosHeader->e_lfanew);
    if (*signature != IMAGE_NT_SIGNATURE) return info;

    auto* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(fullData.data() + dosHeader->e_lfanew + sizeof(DWORD));
    info.is64Bit = (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
    info.isValid = true;

    size_t optionalHeaderSize = fileHeader->SizeOfOptionalHeader;
    size_t sectionOffset = dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize;

    // lista negra de packers y ofuscadores
    std::vector<std::string> knownPackers = { ".vmp", "upx", ".themida", ".aspack", ".enigma", ".mpress" };

    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        size_t currentOffset = sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER));
        if (currentOffset + sizeof(IMAGE_SECTION_HEADER) > fileSize) break;

        auto* secHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(fullData.data() + currentOffset);

        SectionInfo sec;
        char name[9] = { 0 };
        memcpy(name, secHeader->Name, 8);
        sec.name = std::string(name);
        sec.virtualSize = secHeader->Misc.VirtualSize;
        sec.rawSize = secHeader->SizeOfRawData;

        // calcular entropia
        if (sec.rawSize > 0 && secHeader->PointerToRawData + sec.rawSize <= fileSize) {
            std::vector<uint8_t> secData(fullData.begin() + secHeader->PointerToRawData,
                fullData.begin() + secHeader->PointerToRawData + sec.rawSize);
            sec.entropy = CalculateEntropy(secData);
        }
        else {
            sec.entropy = 0.0;
        }

        // heuristica de deteccion
        std::string lowerName = sec.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        sec.isSuspicious = false;

        for (const auto& p : knownPackers) {
            if (lowerName.find(p) != std::string::npos) {
                sec.isSuspicious = true;
                info.warnings.push_back("firma de packer detectada en seccion: " + sec.name);
                break;
            }
        }
        if (sec.entropy > 7.2) {
            sec.isSuspicious = true;
        }

        info.sections.push_back(sec);
    }

    if (info.globalEntropy > 7.4) {
        info.warnings.push_back("entropia global critica. archivo fuertemente encriptado/empaquetado.");
    }

    return info;
}