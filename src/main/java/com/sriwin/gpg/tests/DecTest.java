package com.sriwin.gpg.tests;

import com.sriwin.gpg.constants.EncDecConstants;
import com.sriwin.gpg.service.FileDecryptService;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class DecTest {
  public static void main(String[] args) {
    try {
      String privateKeyFilePath = System.getProperty("user.dir") +
          File.separator + "keys" + File.separator + "_private.asc";

      String privateKeyData = FileUtils.readFileToString(new File(privateKeyFilePath),
          StandardCharsets.UTF_8);
      String encryptedFileName = EncDecConstants.ENC_FILE_NAME;
      char[] password = "Un10n@123".toCharArray();

      FileDecryptService fileDecryptService = new FileDecryptService();
      fileDecryptService.decryptFile(privateKeyData, encryptedFileName, password);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
