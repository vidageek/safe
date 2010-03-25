/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package net.vidageek.security.safe.org.owasp.esapi;

import java.security.SecureRandom;

/**
 * Reference implementation of the Randomizer interface. This implementation
 * builds on the JCE provider to provide a cryptographically strong source of
 * entropy. The specific algorithm used is configurable in ESAPI.properties.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Randomizer
 */
public class Randomizer {

	private final SecureRandom secureRandom = new SecureRandom();

	public String getRandomString(final int length, final char[] characterSet) {
		StringBuilder sb = new StringBuilder();
		for (int loop = 0; loop < length; loop++) {
			int index = secureRandom.nextInt(characterSet.length);
			sb.append(characterSet[index]);
		}
		String nonce = sb.toString();
		return nonce;
	}

	public int getRandomInteger(final int min, final int max) {
		return secureRandom.nextInt(max - min) + min;
	}

}
