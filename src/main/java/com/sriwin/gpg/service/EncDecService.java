package com.sriwin.gpg.service;

import com.sriwin.exception.EncDecException;
import com.sriwin.gpg.constants.EncDecConstants;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;

public abstract class EncDecService implements EncDecConstants {

  public static InputStream getInputStream(String fileData, String encoding)   {
    try(ByteArrayInputStream byteArrayInputStream =  new ByteArrayInputStream(fileData.getBytes(encoding))){
      return byteArrayInputStream;
    } catch (Exception e) {
      throw new EncDecException(e);
    }
  }

  protected PGPSecretKey readPrivateKey(InputStream in, long keyId) throws IOException, PGPException {
    in = PGPUtil.getDecoderStream(in);
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

    PGPSecretKey key = pgpSec.getSecretKey(keyId);

    if (key == null) {
      throw new EncDecException("Can't find encryption key in key ring.");
    }
    return key;
  }

  protected PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
    in = PGPUtil.getDecoderStream(in);
    PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
    PGPPublicKey key = null;
    Iterator rIt = pgpPub.getKeyRings();
    while (key == null && rIt.hasNext()) {
      PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
      Iterator kIt = kRing.getPublicKeys();
      while (key == null && kIt.hasNext()) {
        PGPPublicKey k = (PGPPublicKey) kIt.next();
        if (k.isEncryptionKey()) {
          key = k;
        }
      }
    }
    if (key == null) {
      throw new EncDecException("Can't find encryption key in key ring.");
    }
    return key;
  }


  protected void createFile(String filePath) throws EncDecException {
    try {
      Path path = Paths.get(filePath);
      Files.createDirectories(path.getParent());
      Files.createFile(path);

    } catch (IOException e) {
      throw new EncDecException("Error occurred while creating the file " + filePath, e);
    }
  }

  protected void createFile(String filePath,
                            String fileContent) throws EncDecException {
    try {
      Path path = Paths.get(filePath);
      Files.createDirectories(path.getParent());
      Files.createFile(path);
      FileUtils.writeStringToFile(new File(filePath),
          fileContent, "UTF-8");
    } catch (IOException e) {
      throw new EncDecException("Error occurred while creating the file " + filePath, e);
    }
  }
}
