//
// Created by dwd on 29/07/16.
//

#ifndef METRE_DHPARAMS_H
#define METRE_DHPARAMS_H

#include <openssl/dh.h>
DH *get_dh1024();
DH *get_dh2048();
DH *get_dh4096();


#endif //METRE_DHPARAMS_H
