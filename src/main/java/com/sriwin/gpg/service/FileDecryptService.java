package com.sriwin.gpg.service;

import com.sriwin.exception.EncDecException;
import com.sriwin.gpg.constants.EncDecConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;

public class FileDecryptService extends EncDecService {

  public void decryptFile(String privateKeyData, String encryptedFileName,
                          char[] password)  {
    try {
      // 01 -
      Security.addProvider(new BouncyCastleProvider());

      // 02 -
      InputStream securityKey = getInputStream(privateKeyData, "Cp1252");

      // 03 -
      InputStream inputStream = Files.newInputStream(Paths.get(encryptedFileName));
      InputStream decoderInputStream = PGPUtil.getDecoderStream(inputStream);
      PGPObjectFactory objectFactory = new PGPObjectFactory(decoderInputStream, new BcKeyFingerprintCalculator());

      // 04 -
      Object o = objectFactory.nextObject();
      PGPEncryptedDataList encList = (o instanceof PGPEncryptedDataList)
          ? (PGPEncryptedDataList) o
          : (PGPEncryptedDataList) objectFactory.nextObject();

      //
      PGPPrivateKey pgpPrivateKey = null;
      PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
      Iterator<PGPEncryptedData> itt = encList.getEncryptedDataObjects();
      while (pgpPrivateKey == null && itt.hasNext()) {
        publicKeyEncryptedData = (PGPPublicKeyEncryptedData) itt.next();
        PGPSecretKey pgpSecretKey = readPrivateKey(securityKey, publicKeyEncryptedData.getKeyID());
        pgpPrivateKey = pgpSecretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password));
      }

      //
      if (pgpPrivateKey == null) {
        throw new EncDecException("Secret key message not found.");
      }

      //
      InputStream publicKeyEncryptedDataDataStream = Objects.requireNonNull(publicKeyEncryptedData).getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));
      JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(publicKeyEncryptedDataDataStream);
      PGPCompressedData pgpCompressedData = (PGPCompressedData) pgpObjectFactory.nextObject();
      pgpObjectFactory = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());

      //
      PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory.nextObject();
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      InputStream pgpLiteralDataInputStream = pgpLiteralData.getDataStream();

      //
      int ch;
      while ((ch = pgpLiteralDataInputStream.read()) >= 0) {
        byteArrayOutputStream.write(ch);
      }
      //byteArrayOutputStream.writeTo(Files.newOutputStream(Paths.get(pgpLiteralData.getFileName())));
      byteArrayOutputStream.writeTo(Files.newOutputStream(Paths.get(EncDecConstants.DAT_FILE_NAME)));


      /*try (OutputStream outputStream = Files.newOutputStream(new File(EncDecConstants.DAT_FILE_NAME).toPath())) {
        byteArrayOutputStream.writeTo(outputStream);
      }*/
    } catch (Exception e) {
      throw new EncDecException(e);
    }
  }
}