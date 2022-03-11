/**
 *  Copyright (C) 2008-2017  Telosys project org. ( http://www.telosys.org/ )
 *
 *  Licensed under the GNU LESSER GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *          http://www.gnu.org/licenses/lgpl.html
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.telosys.tools.users.crypto;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class PasswordEncoder {
	
	/**
	 * Encrypt the given password
	 * @param originalPassword
	 * @return
	 */
	public String encrypt(String originalPassword) {
		checkString(originalPassword);
		return encryptPassword(originalPassword);
	}
	
	/**
	 * Verify if the given password is valid according to the given encrypted password
	 * @param originalPassword the password to verify (not encrypted)
	 * @param encryptedPassword the expected encrypted password
	 * @return
	 */
	public boolean verify(String originalPassword, String encryptedPassword) {
		checkString(originalPassword);
		checkString(encryptedPassword);
		return encryptedPassword.equals( encryptPassword(originalPassword) ) ;
	}
	
	private void checkString(String s) {
		if ( s == null ) {
			throw new IllegalArgumentException("Invalid string (null)");
		}
		if ( s.length() == 0 ) {
			throw new IllegalArgumentException("Invalid string (void)");
		}
	}
	
	private static final String SALT1 = "%Naoned!44*";
	private static final String SALT2 = "tElOsYs";
	
	protected String encryptPassword(String password) {
		String passwordWithSalt = SALT1 + password + SALT2 ;
		// in the future use a cryptographic hash algorithms such as 
	    return byteToHex(encryptString(passwordWithSalt) );
	}
	
	/**
	 * Apply cryptographic hash algorithm to the given string
	 * @param input
	 * @return
	 */
	protected byte[] encryptString(String input) {
	    try {
	    	/*
	    	 * Cryptographic hash algorithms such as MD2, MD4, MD5, MD6, HAVAL-128, HMAC-MD5, 
	    	 * DSA (which uses SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160 and SHA-1 
	    	 * are no longer considered secure, because it is possible to have collisions 
	    	 * (little computational effort is enough to find two or more different inputs 
	    	 * that produce the same hash).
	    	 * 
	    	 * Safer alternatives, such as SHA-256, SHA-512, SHA-3 are recommended, 
	    	 * and for password hashing, it's even better to use algorithms that do 
	    	 * not compute too "quickly", like bcrypt, scrypt, argon2 or pbkdf2 
	    	 * because it slows down brute force attacks.
	    	 */
	        MessageDigest crypt = MessageDigest.getInstance("SHA-512"); // SHA-512 is compliant with security recommendations
	        crypt.reset();
	        crypt.update(input.getBytes("UTF-8"));
	        return crypt.digest();
	    }
	    catch(NoSuchAlgorithmException e) {
	    	throw new RuntimeException("Cannot encrypt (NoSuchAlgorithmException)", e);
	    }
	    catch(UnsupportedEncodingException e) {
	    	throw new RuntimeException("Cannot encrypt (UnsupportedEncodingException)", e);
	    }
	}
	
	protected String byteToHex(final byte[] hash) {
	    Formatter formatter = new Formatter();
	    for (byte b : hash) {
	        formatter.format("%02x", b);
	    }
	    String result = formatter.toString();
	    formatter.close();
	    return result;
	}
}
