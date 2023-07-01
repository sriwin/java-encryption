package com.sriwin.enc.tests;

import com.sriwin.enc.constants.EncDecConstants;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

public class EncDec02Test implements EncDecConstants {
  public static void main(String[] args) {
    // 01 -  create empty file
    createFile(new File(FOLDER_PATH + ENC_FILE_NAME));
    createFile(new File(FOLDER_PATH + DEC_FILE_NAME));
    // 02 - encrypt file
    encFile();
    // 03 - decrypt file
    decFile();
    // 04 - compare text file with decrypt file
  }

  private static void createFile(File file) {
    try {
      FileUtils.touch(file);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void encFile() {
    try {
      System.out.println("encFile => Start");
      // 01 - create salt
      Random random = new SecureRandom();
      byte salt[] = new byte[8];
      random.nextBytes(salt);

      // 02 - Generate Initialization Vector (IV)
      byte[] iv = new byte[16];
      random.nextBytes(iv);
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      // 03 - generate secret key
      SecretKeySpec secretKey = getSecretKeySpec(salt);

      // 04 - create cipher
      Cipher cipher = getCipher(ivParameterSpec, secretKey);

      // 05 - gen enc fle
      FileOutputStream fileOutputStream = new FileOutputStream(FOLDER_PATH + ENC_FILE_NAME);
      fileOutputStream.write("Salted__".getBytes(StandardCharsets.UTF_8));
      fileOutputStream.write(salt);
      fileOutputStream.write(iv);

      try (FileInputStream fileInputStream = new FileInputStream(FOLDER_PATH + TXT_FILE_NAME)) {
        processFile(cipher, fileInputStream, fileOutputStream);
      }
      System.out.println("encFile => End");

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }


  private static void decFile() {
    try {
      System.out.println("decFile => Start");

      //01 - generate salt and iv
      byte[] salt = new byte[8];
      byte[] iv = new byte[16];

      // 02 - read salt and iv from enc file
      FileInputStream fileInputStream = new FileInputStream(FOLDER_PATH + ENC_FILE_NAME);
      fileInputStream.read("Salted__".getBytes(StandardCharsets.UTF_8));
      fileInputStream.read(salt);
      fileInputStream.read(iv);

      // 03 - generate secret key
      SecretKeySpec skey = getSecretKeySpec(salt);

      // 04 - generate cipher
      Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
      ci.init(Cipher.DECRYPT_MODE, skey, new IvParameterSpec(iv));

      // 05 - write dec file
      try (FileOutputStream fileOutputStream = new FileOutputStream(FOLDER_PATH + DEC_FILE_NAME)) {
        processFile(ci, fileInputStream, fileOutputStream);
      }
      System.out.println("decFile => End");

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static Cipher getCipher(IvParameterSpec ivParameterSpec,
                                  SecretKeySpec secretKey) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
      return cipher;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Generating AES Key using the user defined password
   *
   * @param salt
   * @return
   */
  private static SecretKeySpec getSecretKeySpec(byte[] salt) {
    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      KeySpec spec = new PBEKeySpec(ENC_DEC_KEY.toCharArray(), salt,
          10000, 128);
      SecretKey tmpSecretKey = factory.generateSecret(spec);
      return new SecretKeySpec(tmpSecretKey.getEncoded(), "AES");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void processFile(Cipher cipher, InputStream in, OutputStream out) {
    try {
      int len;
      byte[] inputBytes = new byte[1024];
      while ((len = in.read(inputBytes)) != -1) {
        byte[] readBytes = cipher.update(inputBytes, 0, len);
        if (readBytes != null) out.write(readBytes);
      }
      byte[] outputBytes = cipher.doFinal();
      if (outputBytes != null) out.write(outputBytes);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}