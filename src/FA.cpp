// g++ -O3 -flto -shared -fPIC -Wall -o LibFA.so FA.cpp -lcrypto

#include <iostream>
#include <stdexcept>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

EC_POINT* CreatePointFromHex(EC_GROUP* pGroup, BN_CTX* pBnCtx, const char* pszHexX, const char* pszHexY)
{
    BIGNUM* pX = nullptr;
    BIGNUM* pY = nullptr;
    BN_hex2bn(&pX, pszHexX);
    BN_hex2bn(&pY, pszHexY);

    EC_POINT* pPoint = EC_POINT_new(pGroup);
    if (!EC_POINT_set_affine_coordinates(pGroup, pPoint, pX, pY, pBnCtx))
    {
        EC_POINT_free(pPoint);
        BN_free(pX);
        BN_free(pY);
        throw std::runtime_error("La définition des coordonnées (x,y) du point a échoué.");
    }

    BN_free(pX);
    BN_free(pY);
    return pPoint;
}

extern "C" 
{
    int CheckFaultBit(
        const char* pszMessageX, const char* pszMessageY,
        const char* pszFaultyMessageX, const char* pszFaultyMessageY,
        const char* pszC1X, const char* pszC1Y,
        int nBitToCheck
    )
    {
        int result = -1; // -1: rien, 0: 0, 1: 1

        EC_GROUP* pGroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
        BN_CTX* pBnCtx = BN_CTX_new();
        BIGNUM* pOrder = BN_new();
        EC_GROUP_get_order(pGroup, pOrder, pBnCtx);

        EC_POINT *pMessage = nullptr, *pFaultyMessage = nullptr, *pC1 = nullptr;
        EC_POINT *pDifference = nullptr, *pResultPos = nullptr, *pResultNeg = nullptr;
        BIGNUM *pScalar2PowI = nullptr, *pScalarNeg = nullptr, *pExponent = nullptr;

        try
        {
            pMessage = CreatePointFromHex(pGroup, pBnCtx, pszMessageX, pszMessageY);
            pFaultyMessage = CreatePointFromHex(pGroup, pBnCtx, pszFaultyMessageX, pszFaultyMessageY);
            pC1 = CreatePointFromHex(pGroup, pBnCtx, pszC1X, pszC1Y);

            pDifference = EC_POINT_new(pGroup);
            EC_POINT_invert(pGroup, pFaultyMessage, pBnCtx);
            EC_POINT_add(pGroup, pDifference, pMessage, pFaultyMessage, pBnCtx);

            pScalar2PowI = BN_new();
            BN_set_word(pScalar2PowI, 2);
            
            pExponent = BN_new();
            BN_set_word(pExponent, nBitToCheck);
            BN_exp(pScalar2PowI, pScalar2PowI, pExponent, pBnCtx);
            
            pResultPos = EC_POINT_new(pGroup);
            EC_POINT_mul(pGroup, pResultPos, nullptr, pC1, pScalar2PowI, pBnCtx);

            if (EC_POINT_cmp(pGroup, pDifference, pResultPos, pBnCtx) == 0)
            {
                result = 0;
            }
            else
            {
                pScalarNeg = BN_new();
                BN_sub(pScalarNeg, pOrder, pScalar2PowI); // -k mod n = n-k mod n
                
                pResultNeg = EC_POINT_new(pGroup);
                EC_POINT_mul(pGroup, pResultNeg, nullptr, pC1, pScalarNeg, pBnCtx);

                if (EC_POINT_cmp(pGroup, pDifference, pResultNeg, pBnCtx) == 0)
                {
                    result = 1;
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Exception C++ : " << e.what() << std::endl;
            result = -1;
        }

        EC_GROUP_free(pGroup);
        BN_CTX_free(pBnCtx);
        BN_free(pOrder);
        EC_POINT_free(pMessage);
        EC_POINT_free(pFaultyMessage);
        EC_POINT_free(pC1);
        EC_POINT_free(pDifference);
        EC_POINT_free(pResultPos);
        EC_POINT_free(pResultNeg);
        BN_free(pScalar2PowI);
        BN_free(pScalarNeg);
        BN_free(pExponent);

        return result;
    }
}