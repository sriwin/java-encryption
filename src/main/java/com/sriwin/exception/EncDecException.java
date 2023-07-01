package com.sriwin.exception;

public class EncDecException extends RuntimeException {
  public EncDecException(String message) {
    super(message);
  }

  public EncDecException(String message, Throwable cause) {
    super(message, cause);
  }

  public EncDecException(Throwable cause) {
    super(cause);
  }

  public String toString() {
    String message = getMessage();
    return (message != null) ? (message) : "";
  }
}
