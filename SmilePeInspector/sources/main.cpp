#include <iostream>
#include <string>
#include <iomanip>
#include <windows.h> // faltaba esta libreria principal aqui
#include "PEParser.h" // ruta directa

void SetColor(int colorCode) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colorCode);
}

int main() {
    SetConsoleTitleA("SMILE // PE-INSPECTOR");

    SetColor(11);
    std::cout << "=========================================\n";
    std::cout << "        SMILE PE-INSPECTOR (x64)         \n";
    std::cout << "=========================================\n\n";

    SetColor(15);
    std::cout << "[>] arrastra el archivo .exe o .dll aqui y presiona enter:\n> ";
    std::string path;
    std::getline(std::cin, path);

    if (!path.empty() && path.front() == '"') path.erase(0, 1);
    if (!path.empty() && path.back() == '"') path.pop_back();

    SetColor(8);
    std::cout << "\n[*] destripando cabeceras pe...\n";

    PEInfo info = AnalyzePE(path);

    if (!info.isValid) {
        SetColor(12);
        std::cout << "[-] error: el archivo no es un ejecutable pe de windows valido (falta mz/nt).\n\n";
        system("pause");
        return 1;
    }

    SetColor(10);
    std::cout << "[+] analisis completado.\n";
    SetColor(15);
    std::cout << "[*] arquitectura: " << (info.is64Bit ? "64-bit (x86_64)" : "32-bit (x86)") << "\n\n";

    SetColor(11);
    std::cout << "[+] SECCIONES DEL ARCHIVO:\n";
    SetColor(8);
    std::cout << "------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(10) << "NOMBRE"
        << " | " << std::setw(12) << "V-SIZE"
        << " | " << std::setw(12) << "RAW-SIZE"
        << " | ENTROPIA\n";
    std::cout << "------------------------------------------------------------------\n";

    for (const auto& sec : info.sections) {
        if (sec.isSuspicious) SetColor(12);
        else SetColor(15);

        std::cout << std::left << std::setw(10) << sec.name
            << " | " << std::setw(12) << sec.virtualSize
            << " | " << std::setw(12) << sec.rawSize
            << " | " << std::fixed << std::setprecision(2) << sec.entropy;

        if (sec.isSuspicious) std::cout << " (CRITICA)\n";
        else if (sec.entropy > 6.5) std::cout << " (Alta)\n";
        else std::cout << " (Normal)\n";
    }

    SetColor(8);
    std::cout << "------------------------------------------------------------------\n\n";

    SetColor(15);
    std::cout << "[*] entropia global: " << std::fixed << std::setprecision(2) << info.globalEntropy << " / 8.00\n\n";

    SetColor(14);
    std::cout << "[!] RESULTADO HEURISTICO:\n";

    if (info.warnings.empty()) {
        SetColor(10);
        std::cout << ">>> LIMPIO: estructura y entropia consistentes.\n";
    }
    else {
        SetColor(12);
        std::cout << ">>> AMENAZA: se detectaron anomalias estructurales.\n";
        for (const auto& w : info.warnings) {
            std::cout << "    - " << w << "\n";
        }
    }

    std::cout << "\n";
    SetColor(15);
    system("pause");
    return 0;
}