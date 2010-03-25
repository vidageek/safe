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
import java.util.UUID;

import net.vidageek.security.safe.org.owasp.esapi.util.EncoderConstants;

import org.apache.log4j.Logger;

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
public class DefaultRandomizer implements Randomizer {

	private final SecureRandom secureRandom = new SecureRandom();

	private final Logger logger = Logger.getLogger(DefaultRandomizer.class);

	/**
	 * {@inheritDoc}
	 */
	public String getRandomString(final int length, final char[] characterSet) {
		StringBuilder sb = new StringBuilder();
		for (int loop = 0; loop < length; loop++) {
			int index = secureRandom.nextInt(characterSet.length);
			sb.append(characterSet[index]);
		}
		String nonce = sb.toString();
		return nonce;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean getRandomBoolean() {
		return secureRandom.nextBoolean();
	}

	/**
	 * {@inheritDoc}
	 */
	public int getRandomInteger(final int min, final int max) {
		return secureRandom.nextInt(max - min) + min;
	}

	/**
	 * {@inheritDoc}
	 */
	public long getRandomLong() {
		return secureRandom.nextLong();
	}

	/**
	 * {@inheritDoc}
	 */
	public float getRandomReal(final float min, final float max) {
		float factor = max - min;
		return secureRandom.nextFloat() * factor + min;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRandomFilename(final String extension) {
		String fn = getRandomString(12, EncoderConstants.CHAR_ALPHANUMERICS) + "." + extension;
		logger.debug("Generated new random filename: " + fn);
		return fn;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRandomGUID() throws EncryptionException {
		return UUID.randomUUID().toString();
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] getRandomBytes(final int n) {
		byte[] result = new byte[n];
		secureRandom.nextBytes(result);
		return result;
	}

}
