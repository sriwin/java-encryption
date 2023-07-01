package com.sriwin.enc.tests;

import com.sriwin.enc.constants.EncDecConstants;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

public class EncDec03Test implements EncDecConstants {

  public static void main(String[] args) {
    try {
      //
      byte[] salt = new byte[8];
      Random random = new SecureRandom();
      random.nextBytes(salt);

      //
      byte[] iv = new byte[128 / 8];
      random.nextBytes(iv);
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      //
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      KeySpec spec = new PBEKeySpec(ENC_DEC_KEY.toCharArray(), salt,
          10000, 128);
      SecretKey tmp = factory.generateSecret(spec);
      SecretKeySpec keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

      encrypt(keySpec, ivParameterSpec, TXT_FILE_NAME, ENC_FILE_NAME, salt, iv);
      decrypt(keySpec);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void decrypt(SecretKey secretKey) {
    try {
      //
      byte[] salt = new byte[8];
      byte[] iv = new byte[128 / 8];

      //
      FileInputStream in = new FileInputStream(FOLDER_PATH + ENC_FILE_NAME);
      in.read("Salted__".getBytes(StandardCharsets.UTF_8));
      in.read(salt);
      in.read(iv);

      //
      Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
      ci.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

      //
      try (FileOutputStream out = new FileOutputStream(FOLDER_PATH + DEC_FILE_NAME)) {
        processFile(ci, in, out);
      }

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec,
                              String plainFile, String encFile,
                              byte[] salt, byte[] iv) {
    try {
      FileOutputStream out = new FileOutputStream(FOLDER_PATH + encFile);
      out.write("Salted__".getBytes(StandardCharsets.UTF_8));
      out.write(salt);
      out.write(iv);

      Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
      ci.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

      try (FileInputStream in = new FileInputStream(FOLDER_PATH + plainFile)) {
        processFile(ci, in, out);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void processFile(Cipher ci, InputStream in, OutputStream out)
      throws javax.crypto.IllegalBlockSizeException,
      javax.crypto.BadPaddingException,
      java.io.IOException {
    byte[] ibuf = new byte[1024];
    int len;
    while ((len = in.read(ibuf)) != -1) {
      byte[] obuf = ci.update(ibuf, 0, len);
      if (obuf != null) out.write(obuf);
    }
    byte[] obuf = ci.doFinal();
    if (obuf != null) out.write(obuf);
  }
}