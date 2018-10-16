package com.ronan;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.sun.xml.internal.ws.util.ASCIIUtility;

public class StreamCipherApplication {

  private static final String ASCII_CHARSET = "US-ASCII";

  public static void main(String[] args) throws
      UnsupportedEncodingException,
      InvalidKeySpecException,
      NoSuchAlgorithmException {

    String chosenOption;

    do {
      System.out.println("MENU: ");
      System.out.println("1. Encrypt Message: ");
      System.out.println("2. Decrypt Message: ");
      System.out.println("3. Quit");
      System.out.println("Enter Option: ");
      Scanner sc = new Scanner(System.in);
      chosenOption = sc.next();

      switch (Integer.parseInt(chosenOption)) {

        case 1:
          System.out.println("Enter Message To Encrypt (ASCII): ");
          String message = sc.next();
          System.out.println("Enter Encryption Password (ASCII): ");
          String password = sc.next();

          byte[] salt = generateSalt();
          System.out.println("SALT Generated (Base64): " + Base64.encodeBase64String(salt));

          byte[] key = deriveKey(password, salt, message.getBytes(ASCII_CHARSET).length);
          System.out.println("Derived Key (Base64): " + Base64.encodeBase64String(key));

          byte[] message_byte_array = message.getBytes(ASCII_CHARSET);
          byte[] cipherText = xorByteArrays(key, message_byte_array);
          System.out.println("CipherText (Base64): " + Base64.encodeBase64String(cipherText));
          break;
        case 2:
          System.out.println("Enter Message To Decrypt (Base64): ");
          String cipherTextString = sc.nextLine();
          cipherText = Base64.decodeBase64(cipherTextString);

          System.out.println("Enter Decryption Password (ASCII): ");
          password = sc.nextLine();

          System.out.println("Enter SALT (Base64): ");
          String salt_string = sc.nextLine();
          salt = Base64.decodeBase64(salt_string);

          key = deriveKey(password, salt, cipherText.length);
          System.out.println("Derived Key (Base64): " + Base64.encodeBase64String(key));

          message_byte_array = xorByteArrays(key, cipherText);
          System.out.println(
              "Message (ASCII): " + ASCIIUtility.toString(message_byte_array, 0, message_byte_array.length));
          break;

        case 3:
          break;

        default:
          System.out.println("Invalid Option Chosen.");
          break;
      }
    }
    while (!chosenOption.equals("3"));
  }

  private static byte[] deriveKey(String password, byte[] salt, int key_length) throws
      UnsupportedEncodingException,
      NoSuchAlgorithmException,
      InvalidKeySpecException {
    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, key_length);
    return new byte[pbeKeySpec.getKeyLength()];
  }

  private static byte[] generateSalt() {
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[32];
    random.nextBytes(salt);
    return salt;
  }

  private static byte[] xorByteArrays(byte[] array1, byte[] array2) {
    byte[] array3 = new byte[array1.length];
    for (int i = 0; i < array3.length; i++) {
      int resultOfXOR = array1[i] ^ array2[i];
      array3[i] = (byte) resultOfXOR;
    }
    return array3;
  }
}
