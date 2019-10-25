//
// Created by iotimc on 2019/10/24.
//

#include <jni.h>

#ifndef WEBAPP_CHECKSIGNATURE_H
#define WEBAPP_CHECKSIGNATURE_H

#endif //WEBAPP_CHECKSIGNATURE_H

#ifndef AESJNIENCRYPT_SIGNACTURECHECK_H
#define AESJNIENCRYPT_SIGNACTURECHECK_H


//合法的APP包名
static const char *app_packageName = "com.iotimc.webapp";
//合法的hashcode -1314815697:这个值是我生成的这个可以store文件的hash值
static const int app_signature_hash_code = -1314815697;

/**
 * 校验APP 包名和签名是否合法
 *
 * 返回值为1 表示合法
 */

jint check_signature(JNIEnv *env, jobject thiz, jobject context);

#endif //AESJNIENCRYPT_SIGNACTURECHECK_H