package com.sriwin.gpg.service;

import com.sriwin.exception.EncDecException;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

public class FileEncryptService extends EncDecService {

  public void encryptFile(String publicKeyFileData, String inputPlainFileName,
                          String outputEncryptedFileName) {
    try {
      // 01 -
      Security.addProvider(new BouncyCastleProvider());

      // 02 -
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
      PGPUtil.writeFileToLiteralData(pgpCompressedDataGenerator.open(byteArrayOutputStream),
          PGPLiteralData.BINARY, new File(inputPlainFileName));
      pgpCompressedDataGenerator.close();

      // 03 -
      PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
          new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
              .setWithIntegrityPacket(true)
              .setSecureRandom(new SecureRandom()).setProvider("BC"));

      // 04 -
      InputStream securityKey = getInputStream(publicKeyFileData, "UTF-8");
      PGPPublicKey publicKey = readPublicKey(securityKey);
      pgpEncryptedDataGenerator.addMethod(
          new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
              .setProvider("BC"));

      // 05 -
      byte[] bytes = byteArrayOutputStream.toByteArray();
      FileOutputStream out = new FileOutputStream(outputEncryptedFileName);
      OutputStream outputStream = pgpEncryptedDataGenerator.open(out, bytes.length);
      outputStream.write(bytes);
      outputStream.close();
      out.close();
    } catch (Exception e) {
      throw new EncDecException(e);
    }
  }
}
