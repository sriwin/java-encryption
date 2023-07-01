package com.sriwin.gpg.utils;

import java.io.File;
import java.io.FileFilter;

public class CheckFileFilter implements FileFilter {
  @Override
  public boolean accept(File file) {
    return file.getName().endsWith(".gpg");
  }
}