#include <string>

std::string base64_encode(unsigned char const* , std::size_t len);
std::string base64_encode(std::string const&);
std::string base64_decode(std::string const& s);