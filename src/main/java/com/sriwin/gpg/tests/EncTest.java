package com.sriwin.gpg.tests;

import com.sriwin.gpg.constants.EncDecConstants;
import com.sriwin.gpg.service.FileEncryptService;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class EncTest {
  public static void main(String[] args) {
    try {
      // 01 -
      String inputFileData = "txt_file.dat";
      String publicKeyFilePath = System.getProperty("user.dir") +
          File.separator + "keys" + File.separator + "_public.asc";
      String publicKeyFileData = FileUtils.readFileToString(new File(publicKeyFilePath),
          StandardCharsets.UTF_8);
      // 02 -
      FileEncryptService fileEncryptService = new FileEncryptService();
      fileEncryptService.encryptFile(publicKeyFileData, inputFileData,
          EncDecConstants.ENC_FILE_NAME);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}