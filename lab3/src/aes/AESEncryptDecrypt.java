package aes;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESEncryptDecrypt {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	// The three methods below throw "checked exceptions", e.g.,
	// NoSuchAlgorithmException and NoSuchProviderException. An exception is
	// generated with something exceptional happens, e.g., an algorithm like AES
	// or a provider like Bouncy Castle cannot be found. A "checked exception"
	// is an exception that we must handle in some way. In the code below we
	// simply "throw" the checked exceptions so that the program terminates with
	// a stack trace.

	private static byte[] encrypt(final Cipher cipher, final Key key,
			final byte[] data) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	private static byte[] decrypt(final Cipher cipher, final Key key,
			final byte[] data) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static void main(final String[] args)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		final String keytext = "thebestsecretkey";
		System.out.println("Key: " + keytext);

		final Cipher cipher = Cipher.getInstance("AES", "BC");
		final Key key = new SecretKeySpec(keytext.getBytes(), "AES");

		final String plaintext = "Hello world!";
		System.out.println("Plaintext: " + plaintext);
		long time = System.currentTimeMillis(), timeUsedEn, timeUsedDe;
		final byte[] ciphertext = encrypt(cipher, key, plaintext.getBytes());
		long timeEncrypt = System.currentTimeMillis();
		System.out.println("Ciphertext: " + Hex.toHexString(ciphertext));
		final String plaintext2 = new String(decrypt(cipher, key, ciphertext));
		long timeDecrypt = System.currentTimeMillis();
		System.out.println("Plaintext (decrypted): " + plaintext2);
		timeUsedEn = timeEncrypt - time;
		timeUsedDe = timeDecrypt - timeEncrypt;
		System.out.println("Time to encrypt: " + timeUsedEn);
		System.out.println("Time to decrypt: " + timeUsedDe);
		assert (plaintext.equals(plaintext2));
	}
}