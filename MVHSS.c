#include "MVHSS.h"

func aFunc;
fmpz_t *vars;
long long allSTermNum=0;

void basicFunction(hPara *pa, BV_Para *bvPara, int type){
    vars = malloc(sizeof(fmpz_t) * pa->varNum);
    flint_rand_t state;
    flint_randinit(state);
    for(int i=0; i<pa->varNum;i++)
    {
        fmpz_init(vars[i]);
        fmpz_randm(vars[i], state,bvPara->msg);
    }
    /*********************prepare the computation task*********************/
    if (type == 1){
        aFunc.tNum=1;
        aFunc.tDegree=(int *)malloc(sizeof(int)*aFunc.tNum);
        aFunc.tSymbol=(int *)malloc(sizeof(int)*aFunc.tNum);
        aFunc.tCon=(int **)malloc(sizeof(int*)*aFunc.tNum);
        aFunc.tDegree[0]=pa->d;
        aFunc.tSymbol[0]=1;
        aFunc.tCon[0]=(int *)malloc(sizeof(int)*aFunc.tDegree[0]);
        for(int j=0; j<aFunc.tDegree[0]; j++)
        {
            aFunc.tCon[0][j]=0;
        }
        allSTermNum+=pow(pa->mSNumPerVar, aFunc.tDegree[0]);
    }else if (type == 2){
        int *tNumByD = malloc(sizeof(int)*(pa->d+1));
        int *tNumByDSum = malloc(sizeof(int)*(pa->d+1));
        tNumByDSum[0]=0;
        for(int i=1; i<=pa->d; i++){
            tNumByD[i]=getComNum(pa->varNum+i-1, i);
            tNumByDSum[i] = tNumByDSum[i-1] + tNumByD[i];
        }

        aFunc.tNum= getComNum(pa->d+pa->varNum, pa->d)-1;//choose maxDg from maxDg+pa.varNum
        aFunc.tDegree=(int *)malloc(sizeof(int)*aFunc.tNum);
        aFunc.tSymbol=(int *)malloc(sizeof(int)*aFunc.tNum);
        aFunc.tCon=(int **)malloc(sizeof(int*)*aFunc.tNum);

        int de=1;
        for(int i=0; i<aFunc.tNum; i++)
        {
            if (i+1>tNumByDSum[de]){de++;}
            aFunc.tDegree[i]=de;
            aFunc.tSymbol[i]=1;
            if (DEBUG){printf("d=%d\n", aFunc.tDegree[i]);}
            aFunc.tCon[i]=(int *)malloc(sizeof(int)*aFunc.tDegree[i]);
            allSTermNum+=pow(pa->mSNumPerVar, aFunc.tDegree[i]);
        }
        //find all terms by degree and variable
        allTermsByDV(aFunc, tNumByD, pa->varNum, pa->d);

        if (DEBUG){
            //check aFunc.tCon
            printf("aFunc.tCon\n");
            for(int i=0; i<aFunc.tNum; i++){
                for(int j=0; j<aFunc.tDegree[i]; j++){
                    printf("%d", aFunc.tCon[i][j]);
                }
                printf("\n");
            }
        }
    }
}

void MVHSS(int repeatTime, hPara pa, BV_Para* bvPara, BV_PK* bvPk, BV_SK* bvSk){
    /**************prepareSharesIndex**************/
    int *tmpArr= malloc(sizeof(int)*pa.m);
    for(int i=0;i<pa.m;i++)
    {
        tmpArr[i]=i+1;
    }
    //combination before merging
    int *data = malloc(sizeof(int)*pa.t);
    pa.sIndex = (int **)(malloc(sizeof(int *) * pa.sNumPerVar));
    for(int i=0; i<pa.sNumPerVar; i++)
    {
        pa.sIndex[i]= ((int*) malloc(sizeof(int) * pa.t));
    }
    combinationUtil(tmpArr, pa.m, pa.t, 0, data, 0, pa.sIndex);

    //free memory
    free(tmpArr);
    tmpArr=NULL;
    free(data);
    data=NULL;
    /********************************************split********************************************/
    //[serverIndex][varIndex][shareIndex]
    share ***serShares = (share ***)(malloc(sizeof(share **) * pa.m));
    for(int i=0; i<pa.m; i++)
    {
        serShares[i] = (share **)(malloc(sizeof(share *) * pa.varNum));
        for(int j=0; j<pa.varNum; j++)
        {
            serShares[i][j] = (malloc(sizeof(share) * pa.sNumPerVar));
        }
    }

    split(serShares, vars, pa, bvPara, bvPk);
    //direct computation
    fmpz_t directRes;
    fmpz_init(directRes);
    fmpz_init(directRes);
    directCompute(directRes, aFunc, vars, bvPara);

    if (DEBUG){
        for(int i=0; i<pa.varNum;i++)
        {
            printf("vars[%d]:", i);
            fmpz_print(vars[i]);
            printf("\n");
        }
    }

    //free memory
    free(vars);
    vars=NULL;
    /********************************************MergeAndCompute********************************************/
    //Calculate all possible combinations ahead of time
    long long *allResSetNum = malloc(sizeof(long long)*(pa.d+1));
    int ***allResSet = malloc(sizeof(int **)*(pa.d+1));
    int **countRes = malloc(sizeof(int*)*(pa.d+1));//Count the number of occurrences of "share" and record the minimum number
    for (int de = 1; de <= pa.d ; de++) {
        allResSetNum[de] = pow(pa.mSNumPerVar, de);//the number of share terms of degree de
        allResSet[de] = malloc(sizeof(int *)*allResSetNum[de]);
        countRes[de] = malloc(sizeof(int *)*allResSetNum[de]);
        for(long long i=0; i<allResSetNum[de]; i++)
        {
            allResSet[de][i] = malloc(sizeof(int)*de);
        }
    }
    shareCombine(allResSet, pa.d, pa);

    if(DEBUG){
        //check allResSet
        for (int de = 1; de <= pa.d ; de++) {
            printf("\n%lld terms combination\n", allResSetNum[de]);
            for(int i=0; i<allResSetNum[de]; i++)
            {
                for(int j=0; j<de; j++)
                {
                    printf("%d", allResSet[de][i][j]);
                }
                printf("\n");
            }
        }
    }


    //compute the state (encrypted or not encrypted)
    int vLIndex[pa.lSNum];
    for(int i=0; i<pa.lSNum;i++)
    {
        vLIndex[i]=i;
    }
    //combination
    int data1[pa.t];
    int ** mSIndex = (int **)(malloc(sizeof(int *) * pa.mSNumPerVar));
    for(int i=0; i<pa.mSNumPerVar; i++)
    {
        mSIndex[i]= (int*) malloc(sizeof(int) * pa.t);
    }
    combinationUtil(vLIndex, pa.lSNum, pa.t, 0, data1, 0, mSIndex);

    if(DEBUG){
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

    share*** mSerShares = (share ***)(malloc(sizeof(share **) * pa.lSNum));
    for(int i=0; i<pa.lSNum; i++)
    {
        mSerShares[i] = (share **)(malloc(sizeof(share *) * pa.varNum));
        for(int j=0; j<pa.varNum; j++)
        {
            mSerShares[i][j] = (share *)(malloc(sizeof(share) * pa.mSNumPerVar));
            for(int k=0; k<pa.mSNumPerVar; k++)
            {
                //mSerShares[i][j][k].sIndex=mSIndex[k];
                if (isInSet(vLIndex[i], mSIndex[k], pa.t))//only cypher
                {
                    mSerShares[i][j][k].state=1;
                }else//only plaintext
                {
                    mSerShares[i][j][k].state=0;
                }
            }
        }
    }

    if(DEBUG){
        //check mSerShares
        printf("mSerShares\n");
        for(int i=0; i<pa.lSNum; i++)
        {
            for(int j=0; j<pa.varNum; j++)
            {
                for(int k=0; k<pa.mSNumPerVar; k++)
                {
                    printf("s%d-v%d-s%d-%d\n", i, j, k, mSerShares[i][j][k].state);
                }
            }
        }
    }

    for (int de = 1; de <= pa.d ; de++) {
        for(long long i=0; i<allResSetNum[de];i++)
        {
            int sCnt[pa.lSNum];
            for (int j = 0; j < pa.lSNum; j++) {//virtual server index
                sCnt[j]=0;
                for(int k=0; k<de; k++)
                {
                    sCnt[j]=sCnt[j]+mSerShares[j][0][allResSet[de][i][k]].state;
                }
            }

            countRes[de][i] = findMinVIdx(sCnt, pa.lSNum);

            if(DEBUG){
                //check sCnt
                for (int j = 0; j < pa.lSNum; j++) {
                    printf("%d-%d,", j, sCnt[j]);
                }

                printf("minVIndx:%d\n", countRes[de][i]);
            }
        }
    }

    //alloc computation for the remaining (pa.m-pa.t) servers
    long long sTermsIndex = 0;
    sTerm* sTerms = malloc(sizeof(sTerm)*allSTermNum);
    for(int i=0; i<aFunc.tNum; i++)
    {
        //according degree to get the share term by spliting
        for(long long j=0; j<allResSetNum[aFunc.tDegree[i]]; j++)
        {
            sTerms[sTermsIndex].conLen = aFunc.tDegree[i];
            sTerms[sTermsIndex].symbol = aFunc.tSymbol[i];
            sTerms[sTermsIndex].tCon = malloc(sizeof(int)*sTerms[sTermsIndex].conLen);
            sTerms[sTermsIndex].sCon = malloc(sizeof(int)*sTerms[sTermsIndex].conLen);
            for(int k=0; k<sTerms[sTermsIndex].conLen; k++)
            {
                sTerms[sTermsIndex].tCon[k] =  aFunc.tCon[i][k];//the variable information
                sTerms[sTermsIndex].sCon[k] = allResSet[aFunc.tDegree[i]][j][k];//the share information
            }
            sTerms[sTermsIndex].ser = countRes[aFunc.tDegree[i]][j];//not real server index, the order of left servers
            sTermsIndex++;
        }
    }

    if(DEBUG){
        //check sTerms
        printf("allSTermNum:%lld\n", allSTermNum);
        for(long long i=0; i<allSTermNum;i++)
        {
            printf("conLen:%d\n", sTerms[i].conLen);
            for (int j = 0; j < sTerms[i].conLen; j++)
            {
                printf("v%d-s%d  ", sTerms[i].tCon[j], sTerms[i].sCon[j]);
            }
            printf("===server:%d\n", sTerms[i].ser);
        }
    }

    //free momery
    for (int de = 1; de <= pa.d ; de++) {
        for(long long i=0; i<allResSetNum[de]; i++)
        {
            free(allResSet[de][i]);
            allResSet[de][i]=NULL;
        }
        free(allResSet[de]);
        allResSet[de]=NULL;
        free(countRes[de]);
        countRes[de]=NULL;
    }
    free(allResSet);
    allResSet=NULL;
    free(countRes);
    countRes=NULL;
    free(allResSetNum);
    allResSetNum=NULL;

    //Close different servers and compute
    clock_t start, end;
    double time = 0;
    cypher **res = malloc(sizeof(cypher*)*pa.sNumPerVar);
    start = clock();
    for(int re=0; re<repeatTime; re++){
        for(int i=0; i<pa.sNumPerVar; i++)
        {
            res[i] = malloc(sizeof(cypher)*pa.lSNum);
            for(int j=0; j<pa.lSNum; j++){
                res[i][j] = (cypher)(malloc(sizeof(fmpz_mod_poly_t) * (pa.k+1)));
                for(int k=0; k<=pa.k; k++){
                    fmpz_mod_poly_init(res[i][j][k], bvPara->ctx_q);
                    fmpz_mod_poly_zero(res[i][j][k], bvPara->ctx_q);
                }
            }
            mergeAndCompute(res[i], pa.sIndex[i], serShares, mSerShares, sTerms, allSTermNum, pa, bvPara, bvPk);
        }
    }

    end = clock();
    time = (double) ((end - start)/repeatTime) / CLOCKS_PER_SEC;
    printf("all server running time: %f ms\n", time * 1000);

    //free memory
    free(sTerms);
    sTerms=NULL;
    for(int i=0; i<pa.m; i++)
    {

        for(int j=0; j<pa.varNum; j++)
        {
            free(serShares[i][j]);
            serShares[i][j]=NULL;
        }
        free(serShares[i]);
        serShares[i]=NULL;
    }
    free(serShares);
    serShares=NULL;
    for(int i=0; i<pa.lSNum; i++)
    {
        for(int j=0; j<pa.varNum; j++)
        {
            free(mSerShares[i][j]);
            mSerShares[i][j]=NULL;
        }
        free(mSerShares[i]);
        mSerShares[i]=NULL;
    }
    free(mSerShares);
    mSerShares=NULL;
    /******************************************Dec and Verification*********************************/
    start = clock();
    cypher finalRes[pa.sNumPerVar];
    for(int re=0; re<repeatTime; re++){
        for(int i=0; i<pa.sNumPerVar; i++)
        {
            finalRes[i] = (cypher)(malloc(sizeof(fmpz_mod_poly_t) * (pa.k+1)));
            for(int j=0; j<=pa.k; j++){
                fmpz_mod_poly_init(finalRes[i][j], bvPara->ctx_q);
                fmpz_mod_poly_zero(finalRes[i][j], bvPara->ctx_q);
            }
            for(int j=0; j<pa.lSNum; j++){
                BV_Add(finalRes[i], finalRes[i], res[i][j], pa.k, bvPara);
            }
        }
    }
//    end = clock();
//    time = (double) ((end - start)/repeatTime) / CLOCKS_PER_SEC;
//    printf("client running time-addition: %f ms\n", time * 1000);
//
//    start = clock();
    fmpz_t decRes[pa.sNumPerVar];
    for (int re=0; re<repeatTime; re++){
        fmpz_init(decRes[0]);
        BV_Dec(decRes[0], finalRes[0], pa.k, bvPara, bvSk);
        fmpz_mod(decRes[0], decRes[0], bvPara->msg);
        if (DEBUG){
            printf("res 0: ");
            fmpz_print(decRes[0]);
            printf("\n");
        }

        int flag=1;
        for(int i=1; i<pa.sNumPerVar; i++)
        {
            fmpz_init(decRes[i]);
            BV_Dec(decRes[i], finalRes[i], pa.k, bvPara, bvSk);
            fmpz_mod(decRes[i], decRes[i], bvPara->msg);
            if (DEBUG){
                printf("res %d: ", i);
                fmpz_print(decRes[i]);
                printf("\n");
            }
            if(!fmpz_equal(decRes[i-1], decRes[i]))//if not equal
            {
                flag=0;
                printf("Closing different servers makes the result different!\n");
            }
        }
        if (flag){
            printf("Verification Successes!\n");
        }else{
            printf("Verification Fails!\n");
        }
    }

    end = clock();
    time = (double) ((end - start)/repeatTime) / CLOCKS_PER_SEC;
//    printf("client running time-dec: %f ms\n", time * 1000);
    printf("client running time: %f ms\n", time * 1000);

    //*compare to direct result
    if (DEBUG){
        printf("direct res: ");
        fmpz_print(directRes);
        printf("\n");

        if(fmpz_equal(decRes[0], directRes))
        {
            printf("The outsourcing result is equal to(=) the direct result!\n");
        }else
        {
            printf("The outsourcing result is not equal to(!=) the direct result!\n");
        }
    }
}
