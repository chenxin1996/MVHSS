#include "split.h"

void split(share*** serShares, fmpz_t* vars, hPara pa, BV_Para* bvPara, BV_PK* bvPk)
{
    /**************prepareShares**************/
    share **varShares = malloc(sizeof(share *)*pa.varNum);
    for(int j=0; j<pa.varNum; j++)
    {
        varShares[j] = (malloc(sizeof(share) * pa.sNumPerVar));
    }
    flint_rand_t state;
    flint_randinit(state);

    for(int i=0; i<pa.varNum;i++)
    {
        fmpz_t add;
        fmpz_init(add);
        fmpz_zero(add);

        for(int j=0; j<pa.sNumPerVar-1; j++)
        {
            varShares[i][j].sIndex=pa.sIndex[j];
            varShares[i][j].state=2;
            fmpz_init(varShares[i][j].plain);
            fmpz_randm(varShares[i][j].plain, state,bvPara->msg);

            fmpz_mod_add(add, add, varShares[i][j].plain, bvPara->ctx_msg);//add shares to get the variable

            //encrypt
            varShares[i][j].cph = (cypher)(malloc(sizeof(fmpz_mod_poly_t) * 2));
            fmpz_mod_poly_init(varShares[i][j].cph[0], bvPara->ctx_q);
            fmpz_mod_poly_init(varShares[i][j].cph[1], bvPara->ctx_q);
            BV_Enc(varShares[i][j].cph, varShares[i][j].plain, bvPara, bvPk);
        }

        varShares[i][pa.sNumPerVar-1].sIndex=pa.sIndex[pa.sNumPerVar-1];
        varShares[i][pa.sNumPerVar-1].state=2;
        fmpz_init(varShares[i][pa.sNumPerVar-1].plain);
        fmpz_mod_sub(varShares[i][pa.sNumPerVar-1].plain, vars[i], add, bvPara->ctx_msg);

        //encrypt
        varShares[i][pa.sNumPerVar-1].cph = (cypher)(malloc(sizeof(fmpz_mod_poly_t) * 2));
        fmpz_mod_poly_init(varShares[i][pa.sNumPerVar-1].cph[0], bvPara->ctx_q);
        fmpz_mod_poly_init(varShares[i][pa.sNumPerVar-1].cph[1], bvPara->ctx_q);
        BV_Enc(varShares[i][pa.sNumPerVar-1].cph, varShares[i][pa.sNumPerVar-1].plain, bvPara, bvPk);
    }

    /**************allocSharesForSevers**************/
    for(int i=0; i<pa.m; i++)
    {
        for(int j=0; j<pa.varNum; j++)
        {
            for(int k=0; k<pa.sNumPerVar; k++)
            {
                serShares[i][j][k].sIndex=varShares[j][k].sIndex;
                if (isInSet(i+1, serShares[i][j][k].sIndex, pa.t))//cyphertext
                {
                    serShares[i][j][k].state=1;
                    serShares[i][j][k].cph = malloc(sizeof(fmpz_mod_poly_t) * 2);
                    fmpz_mod_poly_init(serShares[i][j][k].cph[0], bvPara->ctx_q);
                    fmpz_mod_poly_init(serShares[i][j][k].cph[1], bvPara->ctx_q);
                    fmpz_mod_poly_set(serShares[i][j][k].cph[0], varShares[j][k].cph[0], bvPara->ctx_q);
                    fmpz_mod_poly_set(serShares[i][j][k].cph[1], varShares[j][k].cph[1], bvPara->ctx_q);
                }else//plaintext
                {
                    serShares[i][j][k].state=0;
                    fmpz_init(serShares[i][j][k].plain);
                    fmpz_set(serShares[i][j][k].plain, varShares[j][k].plain);
                }
            }
        }
    }
}

