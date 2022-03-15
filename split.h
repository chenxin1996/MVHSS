#include "BV11.h"

#ifndef MVHSS_SPLIT_H
#define MVHSS_SPLIT_H

/*!
 * Split variables into shares
 * @param serShares: the variable shares of different servers
 * @param vars: the variables
 * @param pa: the parameters from MVHSS
 * @param bvPara: the parameters from cryptosystem
 * @param bvPk: the public key from cryptosystem
 */
void split(share*** serShares, fmpz_t* vars, hPara pa, BV_Para* bvPara, BV_PK* bvPk);

#endif //MVHSS_SPLIT_H
