#include "Entropy.h" // le quitamos la ruta falsa
#include <cmath>
#include <map>

// formula matematica  (0.0 a 8.0)
double CalculateEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;

    std::map<uint8_t, size_t> counts;
    for (uint8_t b : data) counts[b]++;

    double entropy = 0.0;
    double size = static_cast<double>(data.size());

    for (auto const& pair : counts) {
        double p = pair.second / size;
        entropy -= p * std::log2(p);
    }

    return entropy;
}