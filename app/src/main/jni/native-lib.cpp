#include <jni.h>
#include <string>
#import "RSAUtil.h"
#include "BASE64Util.h"

extern "C" {
#include "checksignature.h"
}


const char *UNSIGNATURE = "UNSIGNATURE";
/**
 * RSA加密
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_iotimc_util_RsaJniUtils_encryptJNI(JNIEnv *env, jobject instance, jobject context, jstring s_) {
    //先进行apk被 二次打包的校验
    if (check_signature(env, instance, context) != 1) {
        return env->NewStringUTF(UNSIGNATURE);
    }

    const char *msg = env->GetStringUTFChars(s_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string rsa = RSAUtil::encryptRSAbyPublickey(msgC, NULL);
    rsa = BASE64Util::base64_encodestring(rsa);

    return env->NewStringUTF(rsa.c_str());
}


/**
 * RSA解密
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_iotimc_util_RsaJniUtils_decryptJNI(JNIEnv *env, jobject instance, jobject context, jstring s_) {
    //先进行apk被 二次打包的校验
    if (check_signature(env, instance, context) != 1) {
        return env->NewStringUTF(UNSIGNATURE);
    }

    const char *msg = env->GetStringUTFChars(s_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string rsa = BASE64Util::base64_decodestring(msgC);
    rsa = RSAUtil::decryptRSAbyPrivateKey(rsa);

    return env->NewStringUTF(rsa.c_str());
}





