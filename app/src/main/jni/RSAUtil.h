//
// Created by iotimc on 2019/10/25.
//

#ifndef ENCRYPTDEMO_MYRSA_H
#define ENCRYPTDEMO_MYRSA_H

#include <string>

class RSAUtil{
public:
    static std::string encryptRSAbyPublickey(const std::string& data,int *lenreturn);
    static std::string decryptRSAbyPublicKey(const std::string& data);

    static std::string encryptRSAbyPrivateKey(const std::string& data,int *lenreturn);
    static std::string decryptRSAbyPrivateKey(const std::string& data);
};

#endif //ENCRYPTDEMO_MYRSA_H
