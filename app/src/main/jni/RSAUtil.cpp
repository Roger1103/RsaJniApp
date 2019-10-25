//
// Created by iotimc on 2019/10/25.
//

#include "RSAUtil.h"
#include <cstddef>
#include <stdlib.h>
#include "Log.h"

extern "C" {
#include "openssllib/include/openssl/bio.h"
#include "openssllib/include/openssl/evp.h"
#include "openssllib/include/openssl/rsa.h"
#include "openssllib/include/openssl/pem.h"
}
//公钥
std::string strPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZGpeLJIAZZEvd4eHuIwDof1gZH+g8gCw7gxaI5UiXQBCzlPjGRPuRndB4dS+fUuU39Xxp35MaWj+vSS/b0TbvfyZRzan5CIdy9bzehDUuqjpshGQbB68vY1z2nuj6GYvYwm4OcyODNao1WBqexR5ob5eE77b7ERJATrW/z6qXuQIDAQAB";
//私钥
std::string strPrivateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANkal4skgBlkS93h4e4jAOh/WBkf6DyALDuDFojlSJdAELOU+MZE+5Gd0Hh1L59S5Tf1fGnfkxpaP69JL9vRNu9/JlHNqfkIh3L1vN6ENS6qOmyEZBsHry9jXPae6PoZi9jCbg5zI4M1qjVYGp7FHmhvl4TvtvsREkBOtb/Pqpe5AgMBAAECgYEAg4YXnsT7EebwCzin3dO43iEfpwDseZKQuXD9+uskofS+6XxrhfoOibYYsJEVy6i1ksQWnjFC9ekMwc1NwBar9yfkQaV0eqLGEVnlz9n6A/7OX+zYZ83fxfylG3nm+M8chNzGX/xrK8RwpeG2+S+XFFK4xrUHWNrX2tQ5NgtZ9n0CQQDr0Y6EnpbZbiDK8VOn3wlMiFh6IIjrxn93S3i/55b9mfFA6l2Rb4h+FCdb2TC58JevqISZlYGBgB1oKXvv19ObAkEA668F7rPVbNvLZn0ML+U30irrbhGH8gNrxZfe/tKiraBJi0FwyN8LJHMMCs8zLw9HYq8Ma8hJ4KedxvjvlyspOwJADJ57JOejpOD6ykFdu6b4xWqqaWaiTROjMIwOWx6Wet2pBlNETIsOX8jOTmDx9ZFFXLYE2n8gngBwEmnd4vjGrwJBAMtRZSPEvhS4FGNo8w+KhbpoTkvZEdclPl7qonRgj/iK84cPwFV5nSonmbblgrlRS/sFGgkNczY8Q294J3DYyisCQQCecBfqR4E82WocNQ/vNKhZqmJS3srjeNtkPWO1AORsXbhUDiwSpgC6rM+ugn69luNwqjaslqRHKbzKOeoMkzth";


#define  PADDING   RSA_PKCS1_PADDING          //填充方式
/**
 * 注意注意：不能用一种秘钥同时做加密解密。只能公钥加密+私钥解密 / 私钥加密+公钥解密
 *
 * 公钥存在客户端，私钥存在服务端
 * */

/**
 * 公钥加密
 * */
std::string RSAUtil::encryptRSAbyPublickey(const std::string &data, int *lenreturn) {

    int nPublicKeyLen = strPublicKey.size(); //strPublicKey为base64编码的公钥字符串
    for (int i = 64; i < nPublicKeyLen; i += 64) {
        if (strPublicKey[i] != '\n') {
            strPublicKey.insert(i, "\n");
        }
        i++;
    }
    strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    strPublicKey.append("\n-----END PUBLIC KEY-----\n");


    BIO *bio = NULL;
    RSA *rsa = NULL;
    char *chPublicKey = const_cast<char *>(strPublicKey.c_str());
    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    int flen = RSA_size(rsa);


    std::string strRet;
    strRet.clear();

    char *encryptedText = (char *) malloc(flen + 1);
    memset(encryptedText, 0, flen + 1);

    // 加密函数
    //rsa加密算法是有限制的。受到密钥长度限制。你应该把要加密的内容分块。一块块加密。这样可以避免长度限制问题
    int ret = RSA_public_encrypt(data.length(), (const unsigned char *) data.c_str(), (unsigned char *) encryptedText,
                                 rsa, RSA_PKCS1_PADDING);
    if (ret >= 0) {
        strRet = std::string(encryptedText, ret);
    }

    RSA_free(rsa);
    BIO_free_all(bio);

    free(encryptedText);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return strRet;
}

/**
 * 公钥解密
 * */
std::string RSAUtil::decryptRSAbyPublicKey(const std::string &data) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    LOGE("RSA 公钥解密开始--->%d", 1);
    char *chPublicKey = const_cast<char *>(strPublicKey.c_str());
    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }
    LOGE("RSA 公钥解密开始--->%d", 2);
    r = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    flen = RSA_size(r);
    LOGE("RSA 公钥解密开始--->%d", 3);
    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }
    LOGE("RSA 公钥解密开始--->%d", 4);
    static std::string gkbn;
    gkbn.clear();
    LOGE("RSA 公钥解密开始--->%d", 5);
    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);
    LOGE("RSA 公钥解密开始--->%d", 6);
    int status = RSA_public_decrypt(data.length(), (unsigned char *) data.c_str(),
                                    (unsigned char *) dst, r, RSA_PKCS1_PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {

        LOGE("RSA 公钥解密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;

}

/**
 * 私钥加密
 * */
std::string RSAUtil::encryptRSAbyPrivateKey(const std::string &data, int *lenreturn) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    char *chPrivateKey = const_cast<char *>(strPrivateKey.c_str());
    if ((bio = BIO_new_mem_buf((void *) chPrivateKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }

    lenreturn = &flen;

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_encrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, RSA_PKCS1_PADDING);

    if (status < 0) {

        LOGE("RSA 私钥加密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);

    RSA_free(r);
    BIO_free_all(bio);

    free(dst);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}

/**
 * 私钥解密
 * */
std::string RSAUtil::decryptRSAbyPrivateKey(const std::string &data) {
    int nPrivateKeyLen = strPrivateKey.size(); //strPublicKey为base64编码的公钥字符串
    for(int i = 64; i < nPrivateKeyLen; i+=64)
    {
        if(strPrivateKey[i] != '\n')
        {
            strPrivateKey.insert(i, "\n");
        }
        i++;
    }
    strPrivateKey.insert(0, "-----BEGIN PRIVATE KEY-----\n");
    strPrivateKey.append("\n-----END PRIVATE KEY-----\n");

    int flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    char *chPrivateKey = const_cast<char *>(strPrivateKey.c_str());
    if ((bio = BIO_new_mem_buf((void *) chPrivateKey, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_decrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {

        LOGE("RSA 私钥解密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}
