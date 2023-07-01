package com.sriwin.enc.tests;

import com.google.common.primitives.Bytes;
import com.sriwin.enc.constants.EncDecConstants;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class EncDec01Test implements EncDecConstants {

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
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void decFile() {
    try {
      // Get password
      byte[] secretKeyClear = ENC_DEC_KEY.getBytes();
      byte[] cipherText = FileUtils.readFileToByteArray(new File(FOLDER_PATH + ENC_FILE_NAME));
      byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
      byte[] salt = Arrays.copyOfRange(cipherBytes, 8, 16);
      cipherBytes = Arrays.copyOfRange(
          cipherBytes, 16, cipherBytes.length);

      // Derive key
      byte[] passAndSalt = Bytes.concat(secretKeyClear, salt);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] key = md.digest(passAndSalt);
      SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

      // Derive IV
      md.reset();
      byte[] iv = Arrays.copyOfRange(md.digest(Bytes.concat(key, passAndSalt)), 0, 16);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
      String clearText = new String(cipher.doFinal(cipherBytes));
      FileUtils.writeStringToFile(new File(FOLDER_PATH + DEC_FILE_NAME),
          clearText, StandardCharsets.UTF_8);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void encFile() {
    try {
      // Get password
      byte[] secretKeyClear = ENC_DEC_KEY.getBytes();
      Random random = new SecureRandom();
      byte salt[] = new byte[8];
      random.nextBytes(salt);
      byte[] passAndSalt = Bytes.concat(secretKeyClear, salt);

      //
      String datFileData = FileUtils.readFileToString(new File(FOLDER_PATH + TXT_FILE_NAME),
          StandardCharsets.UTF_8);
      //
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] key = md.digest(passAndSalt);
      md.reset();
      //
      SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
      byte[] iv = Arrays.copyOfRange(md.digest(Bytes.concat(key, passAndSalt)), 0, 16);
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));// Format output

      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      bos.write("Salted__".getBytes(StandardCharsets.UTF_8));
      bos.write(salt);
      bos.write(cipher.doFinal(datFileData.getBytes(StandardCharsets.UTF_8)));
      String cipherText = Base64.getEncoder().encodeToString(bos.toByteArray());
      FileUtils.writeStringToFile(new File(FOLDER_PATH + ENC_FILE_NAME), cipherText, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
