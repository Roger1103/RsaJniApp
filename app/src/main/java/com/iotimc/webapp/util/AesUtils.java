package com.iotimc.webapp.util;

import android.text.TextUtils;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * aes 对称加密工具类
 */
public class AesUtils {
    /*
     * 此处使用AES-128-ECB加密模式，key需要为16位。
     */
    private final static String PASSWORD = "1234567890123456";

    /*
     * 加密
     */
    public static String encrypt(String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext;
        }
        try {
            byte[] result = encrypt(PASSWORD, cleartext);
            return new String(Base64.encode(result, Base64.DEFAULT));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 加密
     *
     * @param password 加密密码
     * @param clear    明文
     * @return
     * @throws Exception
     */
    private static byte[] encrypt(String password, String clear) throws Exception {
        // 创建AES秘钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(), "AES/CBC/PKCS5PADDING");
        // 创建密码器
        Cipher cipher = Cipher.getInstance("AES");
        // 初始化加密器
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        // 加密
        return cipher.doFinal(clear.getBytes("UTF-8"));
    }


    /*
     * 解密
     */
    public static String decrypt(String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext;
        }
        try {
            byte[] result = decrypt(Base64.decode(cleartext, Base64.DEFAULT), PASSWORD);
            return new String(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param content
     * @param password
     * @return
     * @throws Exception
     */
    private static byte[] decrypt(byte[] content, String password) throws Exception {
        // 创建AES秘钥
        SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES/CBC/PKCS5PADDING");
        // 创建密码器
        Cipher cipher = Cipher.getInstance("AES");
        // 初始化解密器
        cipher.init(Cipher.DECRYPT_MODE, key);
        // 解密
        return cipher.doFinal(content);
    }


}
