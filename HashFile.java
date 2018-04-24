import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
/**
 * 
 * @author Sheetal
 *
 */
public class HashFile {
	/*
	 * Method Calculates the HashKey for a given File
	 */
	public static String getHashFile(String fileName) {
	    byte[] buffer= new byte[8192];
	    int count;
	    MessageDigest digest = null;
		try {
			// SHA-256 used for hashing
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//Read the contents of file to create Hash
	    BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(new FileInputStream(fileName));
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
	    try {
			while ((count = bis.read(buffer)) > 0) {
			    digest.update(buffer, 0, count);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}finally {
			try {
				bis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	    byte[] hash = digest.digest();
	    return convertByteArrayToHexString(hash);
	    
	}
	/*
	 * Method to convert the byte[] hash to Hex String
	 */
	private static String convertByteArrayToHexString(byte[] arrayBytes) {
	    StringBuffer sb = new StringBuffer();
	    for (int i = 0; i < arrayBytes.length; i++) {
	        sb.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16).substring(1));
	    }
	    return sb.toString();
	}

}
