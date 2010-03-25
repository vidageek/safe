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
 * An ExecutorException should be thrown for any problems that occur when
 * encoding or decoding data.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncodingException extends RuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Creates a new instance of EncodingException.
	 * 
	 * @param userMessage
	 *            the message displayed to the user
	 */
	public EncodingException(final String userMessage) {
		super(userMessage);
	}

	/**
	 * Instantiates a new EncodingException.
	 * 
	 * @param userMessage
	 *            the message displayed to the user
	 * @param cause
	 *            the cause
	 */
	public EncodingException(final String userMessage, final Throwable cause) {
		super(userMessage, cause);
	}

}
