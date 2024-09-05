//
// Created by dave on 05/09/2024.
//

#ifndef METRE_SOCKADDR_CAST_H
#define METRE_SOCKADDR_CAST_H

#include <sys/socket.h>
#include <type_traits>

namespace Metre {
    namespace detail {
        template<typename T, typename Q>
        struct constlike {
            using type = std::conditional<std::is_const<T>::value, const typename std::remove_const<Q>::type, Q>::type;
        };

        template<typename T, decltype(sockaddr::sa_family) AF>
        struct sockaddr_family {
            using base_type = sockaddr;
            using type = constlike<T, base_type>::type;
        };

        template<typename T>
        struct sockaddr_family<T, AF_INET> {
            using base_type = struct sockaddr_in;
            using type = constlike<T, base_type>::type;
        };

        template<typename T>
        struct sockaddr_family<T, AF_INET6> {
            using base_type = struct sockaddr_in6;
            using type = constlike<T, base_type>::type;
        };
    }

    template<decltype(sockaddr::sa_family) AF, typename SOCKADDR, typename SOCKADDR_OUT = typename detail::sockaddr_family<SOCKADDR, AF>::type>
    SOCKADDR_OUT *sockaddr_cast(SOCKADDR *sa) {
        return reinterpret_cast<SOCKADDR_OUT *>(sa);
    }
}

#endif //METRE_SOCKADDR_CAST_H
