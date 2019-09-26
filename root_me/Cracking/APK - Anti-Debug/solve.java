import java.lang.*; 
import java.util.*;
import java.security.MessageDigest;
// MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
// messageDigest.reset();
// byte[] arrayOfByte = messageDigest.digest(paramString.getBytes());

public class solve { 
  
    public static byte[] hexStringToByteArray(String paramString) {
        int i = paramString.length() - 1;
        byte[] arrayOfByte = new byte[i / 2 + 1];
        for (byte b = 0; b < i; b += 2)
            arrayOfByte[b / 2] = (byte)((Character.digit(paramString.charAt(b), 16) << 4) + Character.digit(paramString.charAt(b + 1), 16)); 
        return arrayOfByte;
    }

    public static void main(String[] args) 
    { 
        byte[] arr = hexStringToByteArray("622a751d6d12b46ad74049cf50f2578b871ca9e9447a98b06c21a44604cab0b4");
        System.out.println(new String(arr));   
    }
} 