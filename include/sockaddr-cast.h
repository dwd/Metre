//
// Created by dave on 05/09/2024.
//

#ifndef METRE_SOCKADDR_CAST_H
#define METRE_SOCKADDR_CAST_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <type_traits>

namespace Metre {
    namespace detail {
        template<typename T, typename Q>
        struct constlike {
            using type = std::conditional_t<std::is_const_v<T>, const typename std::remove_const_t<Q>, Q>;
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

        template<typename A, typename B, typename C, typename D, typename R>
        D fourth_param(R (*)(A, B, C, D)) {
            return D{};
        }

        using inet_ntop_len_t = decltype(fourth_param(inet_ntop));
    }

    template<decltype(sockaddr::sa_family) AF, typename SOCKADDR, typename SOCKADDR_OUT = typename detail::sockaddr_family<SOCKADDR, AF>::type>
    SOCKADDR_OUT *sockaddr_cast(SOCKADDR *sa) {
        return reinterpret_cast<SOCKADDR_OUT *>(sa);
    }

    class unknown_address_family : public std::logic_error {
    public:
        unknown_address_family() : std::logic_error(std::strerror(errno)) {}
        explicit unknown_address_family(int err) : std::logic_error(std::strerror(err)) {}
    };

    template<typename SA>
    std::string address_tostring(SA * sa) {
        // Figure out the family, first:
        auto * const sa_base = sockaddr_cast<AF_UNSPEC>(sa);
        if (sa_base->sa_family == AF_INET) {
            auto * const sin = sockaddr_cast<AF_INET>(sa);
            std::string buf;
            buf.resize(INET_ADDRSTRLEN + 1);
            if (auto l = inet_ntop(AF_INET, &(sin->sin_addr), buf.data(), static_cast<detail::inet_ntop_len_t >(buf.size())); l) {
                buf.resize(buf.find('\0'));
                return buf;
            }
            throw unknown_address_family();
        }
        if (sa_base->sa_family == AF_INET6) {
            auto * const sin6 = sockaddr_cast<AF_INET6>(sa);
            std::string buf;
            buf.resize(INET6_ADDRSTRLEN + 1);
            if (auto l = inet_ntop(AF_INET6, &(sin6->sin6_addr), buf.data(), static_cast<detail::inet_ntop_len_t>(buf.size())); l) {
                buf.resize(buf.find('\0'));
                return buf;
            }
            throw unknown_address_family();
        }
        throw unknown_address_family(EAFNOSUPPORT);
    }

    template<typename SA>
    unsigned short address_toport(SA * sa) {
        // Figure out the family, first:
        auto * const sa_base = sockaddr_cast<AF_UNSPEC>(sa);
        if (sa_base->sa_family == AF_INET) {
            return ntohs(sockaddr_cast<AF_INET>(sa)->sin_port);
        }
        if (sa_base->sa_family == AF_INET6) {
            return ntohs(sockaddr_cast<AF_INET6>(sa)->sin6_port);
        }
        throw unknown_address_family(EAFNOSUPPORT);
    }
}

#endif //METRE_SOCKADDR_CAST_H
