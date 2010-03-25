package net.vidageek.security.safe.el;

import org.owasp.esapi.Encoder;

/**
 * @author jonasabreu
 * 
 */
final public class Sanitizer {

	private final String key;

	public Sanitizer(final Encoder encoder, final String key) {
		this.key = key;
	}

}
