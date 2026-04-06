#pragma once
#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct SectionInfo {
    std::string name;
    DWORD virtualSize;
    DWORD rawSize;
    double entropy;
    bool isSuspicious;
};

struct PEInfo {
    bool isValid;
    bool is64Bit;
    double globalEntropy;
    std::vector<SectionInfo> sections;
    std::vector<std::string> warnings;
};

// lee las cabeceras dos/nt
PEInfo AnalyzePE(const std::string& filePath);