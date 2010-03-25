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

/**
 * The code of this class was extracted from OWASP Enterprise Security API (ESAPI).
 * Svn repo: http://owasp-esapi-java.googlecode.com/svn/trunk
 * Revision: 1222
 * 
 * After extraction, modifications were performed by Jonas Abreu (jonas at vidageek dot net) to fit this project's needs
 */
/**
 * An EncryptionException should be thrown for any problems related to
 * encryption, hashing, or digital signatures.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncryptionException extends RuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new EncryptionException.
	 */
	protected EncryptionException() {
		// hidden
	}

	/**
	 * Creates a new instance of EncryptionException.
	 * 
	 * @param userMessage
	 *            the message displayed to the user
	 * @param logMessage
	 *            the message logged
	 */
	public EncryptionException(final String userMessage) {
		super(userMessage);
	}

	/**
	 * Instantiates a new EncryptionException.
	 * 
	 * @param userMessage
	 *            the message displayed to the user
	 * @param logMessage
	 *            the message logged
	 * @param cause
	 *            the cause
	 */
	public EncryptionException(final String userMessage, final Throwable cause) {
		super(userMessage, cause);
	}
}
