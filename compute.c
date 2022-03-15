#include "compute.h"

void mergeAndCompute(cypher *res, int* cIndex, share*** serShares, share*** mSerShares, sTerm* sTerms, long long allSTermNum, hPara pa, BV_Para* bvPara, BV_PK* bvPk)
{
    /*merge*/
    int rLIndex[pa.lSNum];

    int cnter=0;
    for(int i=0;i<pa.m;i++)
    {
        if(isInSet(i+1, cIndex, pa.t))
        {
            continue;
        }else
        {
            rLIndex[cnter++]=i+1;
        }
    }

    //combination
    int data[pa.t];
    int ** mSIndex = (int **)(malloc(sizeof(int *) * pa.mSNumPerVar));
    for(int i=0; i<pa.mSNumPerVar; i++)
    {
        mSIndex[i]= (int*) malloc(sizeof(int) * pa.t);
    }
    combinationUtil(rLIndex, pa.lSNum, pa.t, 0, data, 0, mSIndex);

    if (DEBUG)
    {
        //check mSIndex
        printf("mSIndex\n");
        for(int i=0; i<pa.mSNumPerVar; i++)
        {
            for(int j=0; j<pa.t; j++)
            {
                printf("%d", mSIndex[i][j]);
            }
            printf("\n");
        }
    }


    //convert the virtual server index to real server index
    for(int i=0; i<pa.lSNum; i++)
    {
        for(int j=0; j<pa.varNum; j++)
        {
            for(int k=0; k<pa.mSNumPerVar; k++)
            {
                mSerShares[i][j][k].sIndex=mSIndex[k];
                if (mSerShares[i][j][k].state==1)//only cypher
                {
                    mSerShares[i][j][k].cph = malloc(sizeof(fmpz_mod_poly_t) * 2);
                    fmpz_mod_poly_init(mSerShares[i][j][k].cph[0], bvPara->ctx_q);
                    fmpz_mod_poly_zero(mSerShares[i][j][k].cph[0], bvPara->ctx_q);
                    fmpz_mod_poly_init(mSerShares[i][j][k].cph[1], bvPara->ctx_q);
                    fmpz_mod_poly_zero(mSerShares[i][j][k].cph[1], bvPara->ctx_q);
                }else if(mSerShares[i][j][k].state==0)//only plaintext
                {
                    fmpz_init(mSerShares[i][j][k].plain);
                    fmpz_zero(mSerShares[i][j][k].plain);
                }
            }
        }
    }

    for(int i=0; i<pa.lSNum; i++)
    {
        int ser=rLIndex[i];
        //merge shares for ser
        for (int j=0; j<pa.varNum; j++)
        {
            for (int k=0; k<pa.sNumPerVar; k++)
            {
                //find serShares merge into which mSerShares
                int into = findMergeInto(mSIndex, serShares[ser-1][j][k].sIndex, pa);
                if (mSerShares[i][j][into].state==1)//merge into cypher
                {
                    if (serShares[ser-1][j][k].state==1)//cypher
                    {
                        BV_Add(mSerShares[i][j][into].cph, mSerShares[i][j][into].cph, serShares[ser-1][j][k].cph, 1, bvPara);
                    }else//plaintext
                    {
                        cypher temp = (cypher)(malloc(sizeof(fmpz_mod_poly_t) * 2));
                        fmpz_mod_poly_init(temp[0], bvPara->ctx_q);
                        fmpz_mod_poly_init(temp[1], bvPara->ctx_q);
                        BV_Enc(temp, serShares[ser-1][j][k].plain, bvPara, bvPk);
                        BV_Add(mSerShares[i][j][into].cph, mSerShares[i][j][into].cph, temp, 1, bvPara);
                    }
                }else//merge into plaintext
                {
                    fmpz_mod_add(mSerShares[i][j][into].plain, mSerShares[i][j][into].plain, serShares[ser-1][j][k].plain, bvPara->ctx_msg);
                }
            }
        }
    }

    /*compute*/
    //allSTermNum
    fmpz_t *plianRes = malloc(sizeof(fmpz_t)*pa.lSNum);
    for(int i=0; i<pa.lSNum; i++){
        fmpz_init(plianRes[i]);
        fmpz_zero(plianRes[i]);
    }

    for(long long i=0; i<allSTermNum; i++)
    {
        //sTerms[i].ser computes sTerms.con with mSerShares[sTerms[i].ser]
        fmpz_t multiPlain;
        fmpz_init(multiPlain);
        fmpz_one(multiPlain);
        int cyCnter=0;
        int *cyRecord = malloc(sizeof(int)*pa.k);
        for(int j=0; j<pa.k; j++){
            cyRecord[j]=-1;
        }
        for(int j=0; j<sTerms[i].conLen; j++)
        {
            if (mSerShares[sTerms[i].ser][sTerms[i].tCon[j]][sTerms[i].sCon[j]].state==0)//multiple all plaintexts
            {
                fmpz_mod_mul(multiPlain, multiPlain, mSerShares[sTerms[i].ser][sTerms[i].tCon[j]][sTerms[i].sCon[j]].plain, bvPara->ctx_msg);
            }else if (mSerShares[sTerms[i].ser][sTerms[i].tCon[j]][sTerms[i].sCon[j]].state==1)//record cyphertext information
            {
                cyRecord[cyCnter++]=j;
            }
        }


        if (DEBUG){
            if(cyCnter>pa.k){
                printf("%lld ERROR!! %d\n", i, cyCnter);
            }
        }
        //multiple cyphertext
        if(cyCnter==0){
            //no cyphertext: encrypt the plaintext result to get temp result
            if (sTerms[i].symbol==1){
                fmpz_mod_add(plianRes[sTerms[i].ser], plianRes[sTerms[i].ser], multiPlain, bvPara->ctx_msg);
            }else{
                fmpz_mod_sub(plianRes[sTerms[i].ser], plianRes[sTerms[i].ser], multiPlain, bvPara->ctx_msg);
            }
        }else if (cyCnter==1){
            //one cyphertext: multiple the cyphertext with multiPlain
            cypher temp = malloc(sizeof(fmpz_mod_poly_t) * 2);
            fmpz_mod_poly_init(temp[0], bvPara->ctx_q);
            fmpz_mod_poly_init(temp[1], bvPara->ctx_q);

            int j = cyRecord[0];
            BV_Scalar_Mult(temp, mSerShares[sTerms[i].ser][sTerms[i].tCon[j]][sTerms[i].sCon[j]].cph, multiPlain, 1, bvPara);

            if (sTerms[i].symbol==1) {
                BV_Add(res[sTerms[i].ser], res[sTerms[i].ser], temp, 1, bvPara);
            }else {
                BV_Sub(res[sTerms[i].ser], res[sTerms[i].ser], temp, 1, bvPara);
            }
        }else if (cyCnter>=2){
            cypher *array = malloc(sizeof(cypher)*(pa.k-1));
            for(int j=0; j<pa.k-1; j++){
                array[j] = malloc(sizeof(fmpz_mod_poly_t) * (j+3));
                for(int k=0; k<(j+3); k++){
                    fmpz_mod_poly_init(array[j][k], bvPara->ctx_q);
                }
            }

            BV_Mult(array[0], mSerShares[sTerms[i].ser][sTerms[i].tCon[cyRecord[0]]][sTerms[i].sCon[cyRecord[0]]].cph, mSerShares[sTerms[i].ser][sTerms[i].tCon[cyRecord[1]]][sTerms[i].sCon[cyRecord[1]]].cph, 1, bvPara);
            int lpTime = cyCnter-2, index = 0;
            while (lpTime>0){
                BV_Mult(array[index+1], mSerShares[sTerms[i].ser][sTerms[i].tCon[cyRecord[index+2]]][sTerms[i].sCon[cyRecord[index+2]]].cph, array[index], index+2, bvPara);
                index++;
                lpTime--;
            }

            BV_Scalar_Mult(array[cyCnter-2], array[cyCnter-2], multiPlain, cyCnter, bvPara);

            if (sTerms[i].symbol==1){
                BV_Add(res[sTerms[i].ser], res[sTerms[i].ser], array[cyCnter-2], cyCnter, bvPara);
            }else{
                BV_Sub(res[sTerms[i].ser], res[sTerms[i].ser], array[cyCnter-2], cyCnter, bvPara);
            }
        }
    }
    //at last, encrypt the plaintext and add it to cyphertext
    cypher temp = malloc(sizeof(fmpz_mod_poly_t) * 2);
    fmpz_mod_poly_init(temp[0], bvPara->ctx_q);
    fmpz_mod_poly_init(temp[1], bvPara->ctx_q);
    for(int i=0; i<pa.lSNum; i++){
        BV_Enc(temp, plianRes[i], bvPara, bvPk);
        // add temp to final result
        BV_Add(res[sTerms[i].ser], res[sTerms[i].ser], temp, 1, bvPara);
    }
}

void directCompute(fmpz_t directRes, func aFunc, fmpz_t *vars, BV_Para* bvPara)
{
    for(int i=0; i<aFunc.tNum; i++)
    {
        fmpz_t termRes;
        fmpz_init(termRes);
        fmpz_one(termRes);
        for(int j=0; j<aFunc.tDegree[i]; j++)
        {
            fmpz_mod_mul(termRes, termRes, vars[aFunc.tCon[i][j]], bvPara->ctx_msg);
        }
        if (aFunc.tSymbol[i]==1) {
            fmpz_mod_add(directRes, directRes, termRes, bvPara->ctx_msg);
        }else {
            fmpz_mod_sub(directRes, directRes, termRes, bvPara->ctx_msg);
        }
    }
}

void shareCombine(int ***allResSet, int maxDg, hPara pa){
    for (int de = 1; de <= maxDg ; de++) {
        int *currentSet = malloc(sizeof(int)*de);

        //Get all share term
        cartesianProduct(allResSet[de], pa.mSNumPerVar,currentSet,de ,0);
    }
};

int findMergeInto(int **mSIndex, int *index, hPara pa) {
    int maxNumber=0;
    int maxNumberIndex=0;
    for(int i=0;i<pa.mSNumPerVar;i++)
    {
        int numOfSame=0;
        for(int j=0; j<pa.t; j++)
        {
            if (isInSet(index[j], mSIndex[i], pa.t))
            {
                numOfSame++;
            }
        }
        if(numOfSame>maxNumber)
        {
            maxNumber=numOfSame;
            maxNumberIndex=i;
        }
    }
    return maxNumberIndex;
}

void allTermsByDV(func aFunc, int *tNumByD, int varNum, int maxDg){

    int tIndex=0;
    for(int i=1; i<=maxDg; i++){
        int *currentTerm = malloc(sizeof(int)*i);
        int **terms = malloc(sizeof(int *)*tNumByD[i]);
        for(int j=0; j<tNumByD[i]; j++){
            terms[j] = malloc(sizeof(int)*i);
        }
        geTermsByDV(terms, currentTerm, i, varNum, 0, 0);

        if (DEBUG){
            //check terms
            printf("terms\n");
            for(int j=0; j<tNumByD[i]; j++){
                for(int k=0; k<i; k++){
                    printf("%d", terms[j][k]);
                }
                printf("\n");
            }
        }
        for(int j=0; j<tNumByD[i]; j++){
            for(int k=0; k<i; k++){
                aFunc.tCon[tIndex][k]=terms[j][k];
            }
            tIndex++;
        }
    }
}

int termsIndex;
void geTermsByDV(int **terms, int *currentTerm, int degree, int varNum, int start, int level){
    if (level==0){
        termsIndex=0;
    }
    if (level==degree){
        for(int i=0; i<degree; i++){
            terms[termsIndex][i]=currentTerm[i];
        }
        termsIndex++;
    }else{
        for(int i=start; i<varNum; i++){
            currentTerm[level]=i;
            geTermsByDV(terms, currentTerm, degree, varNum, i, level+1);
        }
    }
}


