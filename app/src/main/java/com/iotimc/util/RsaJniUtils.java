package com.iotimc.util;

import android.content.Context;

public class RsaJniUtils {

    static {
        System.loadLibrary("rsa");
    }

    public native String encryptJNI(Context context,String encryptTextData);

    public native String decryptJNI(Context context,String decryptTextData);
}
