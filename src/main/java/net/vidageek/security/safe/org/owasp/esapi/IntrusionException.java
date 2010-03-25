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

import org.apache.log4j.Logger;

/**
 * An IntrusionException should be thrown anytime an error condition arises that
 * is likely to be the result of an attack in progress. IntrusionExceptions are
 * handled specially by the IntrusionDetector, which is equipped to respond by
 * either specially logging the event, logging out the current user, or
 * invalidating the current user's account.
 * <P>
 * Unlike other exceptions in the ESAPI, the IntrusionException is a
 * RuntimeException so that it can be thrown from anywhere and will not require
 * a lot of special exception handling.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class IntrusionException extends RuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The logger. */
	protected final Logger logger = Logger.getLogger(IntrusionException.class);

	/**
     *
     */
	protected String logMessage = null;

	/**
	 * Creates a new instance of IntrusionException.
	 * 
	 * @param userMessage
	 *            the message to display to users
	 * @param logMessage
	 *            the message logged
	 */
	public IntrusionException(final String userMessage) {
		super(userMessage);
	}

	/**
	 * Instantiates a new intrusion exception.
	 * 
	 * @param userMessage
	 *            the message to display to users
	 * @param logMessage
	 *            the message logged
	 * @param cause
	 *            the cause
	 */
	public IntrusionException(final String userMessage, final Throwable cause) {
		super(userMessage, cause);
	}

	/**
	 * Returns a String containing a message that is safe to display to users
	 * 
	 * @return a String containing a message that is safe to display to users
	 */
	public String getUserMessage() {
		return getMessage();
	}

}
