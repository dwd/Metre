/* 
   base64.cpp and base64.h

   Copyright (C) 2004-2008 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

#include "base64.h"
#include <iostream>
#include <array>
#include <utility>

static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";


static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::byte operator+(std::byte a, std::byte b) {
    return static_cast<std::byte>(std::to_integer<unsigned char>(a) + std::to_integer<unsigned char>(b));
}

std::string base64_encode(unsigned char const* bytes_to_encode, std::size_t in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    std::array<std::byte, 3> char_array_3 = {};
    std::array<std::byte, 4> char_array_4 = {};

    while (in_len--) {
        char_array_3[i] = static_cast<std::byte>(*(bytes_to_encode++));
        i++;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & std::byte{0xfc}) >> 2;
            char_array_4[1] = ((char_array_3[0] & std::byte{0x03}) << 4) + ((char_array_3[1] & std::byte{0xf0}) >> 4);
            char_array_4[2] = ((char_array_3[1] & std::byte{0x0f}) << 2) + ((char_array_3[2] & std::byte{0xc0}) >> 6);
            char_array_4[3] = char_array_3[2] & std::byte{0x3f};

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[to_integer<int>(char_array_4[i])];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = std::byte{0};

        char_array_4[0] = (char_array_3[0] & std::byte{0xfc}) >> 2;
        char_array_4[1] = ((char_array_3[0] & std::byte{0x03}) << 4) + ((char_array_3[1] & std::byte{0xf0}) >> 4);
        char_array_4[2] = ((char_array_3[1] & std::byte{0x0f}) << 2) + ((char_array_3[2] & std::byte{0xc0}) >> 6);
        char_array_4[3] = char_array_3[2] & std::byte{0x3f};

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[to_integer<int>(char_array_4[j])];

        while(i++ < 3)
            ret += '=';

    }

    return ret;

}

std::string base64_encode(std::string_view const & s) {
    return base64_encode(reinterpret_cast<const unsigned char *>(s.data()), s.size());
}

std::string base64_decode(std::string_view const& encoded_string) {
    std::size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    std::array<std::byte, 4> char_array_4 = {};
    std::array<std::byte, 4> char_array_3 = {};
    std::string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i] = static_cast<std::byte>(encoded_string[in_]);
        i++; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = static_cast<std::byte>(base64_chars.find(static_cast<char>(std::to_underlying(char_array_4[i]))));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & std::byte{0x30}) >> 4);
            char_array_3[1] = ((char_array_4[1] & std::byte{0xf}) << 4) + ((char_array_4[2] & std::byte{0x3c}) >> 2);
            char_array_3[2] = ((char_array_4[2] & std::byte{0x3}) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += static_cast<char>(std::to_underlying(char_array_3[i]));
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = std::byte{0};

        for (j = 0; j <4; j++)
            char_array_4[j] = static_cast<std::byte>(base64_chars.find(static_cast<char>(std::to_underlying(char_array_4[i]))));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & std::byte{0x30}) >> 4);
        char_array_3[1] = ((char_array_4[1] & std::byte{0xf}) << 4) + ((char_array_4[2] & std::byte{0x3c}) >> 2);
        char_array_3[2] = ((char_array_4[2] & std::byte{0x3}) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += static_cast<char>(std::to_underlying(char_array_3[j]));
    }

    return ret;
}
