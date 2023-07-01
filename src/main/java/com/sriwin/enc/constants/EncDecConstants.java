package com.sriwin.enc.constants;

public interface EncDecConstants {
  String CIPHER_ID = "AES/CBC/PKCS5Padding";
  String BOUNCY_CASTLE_PROVIDER_ID = "BC";
  String ALGORITHM = "AES";
  int KEY_LEN_BITS = 256;

  //
  String ENC_DEC_KEY = "";
  String FOLDER_PATH = "C:\\temp\\secrets\\";
  String ENC_FILE_NAME = "enc_file.enc";
  String DEC_FILE_NAME = "dec_file.dec";
  String TXT_FILE_NAME = "txt_file.dat";

}