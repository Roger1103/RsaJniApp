//
// Created by iotimc on 2019/10/25.
//

#ifndef ENCRYPTDEMO_MYBASE64_H
#define ENCRYPTDEMO_MYBASE64_H

#include <stdio.h>
#include <string>

class BASE64Util {

public:
    static std::string base64_decode(const std::string& encoded_bytes,
                                     int *decoded_length) ;
    static std::string base64_encode(const std::string& decoded_bytes,
                                     size_t decoded_length) ;



    static std::string base64_encodestring(const std::string &text );
    static  std::string base64_decodestring(const std::string &text );

};


#endif //ENCRYPTDEMO_MYBASE64_H
