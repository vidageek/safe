package net.vidageek.security.safe.el;

import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;

/**
 * @author jonasabreu
 * 
 */
final public class Sanitizer {

	private final String suspectContent;
	private final Encoder encoder;

	public Sanitizer(final Encoder encoder, final String suspectContent) {
		this.encoder = encoder;
		this.suspectContent = suspectContent;
	}

	@Override
	public String toString() {
		return getHtml();
	}

	public String getHtml() {
		return encoder.encodeForHTML(suspectContent);
	}

	public String getCss() {
		return encoder.encodeForCSS(suspectContent);
	}

	public String getAttr() {
		return encoder.encodeForHTMLAttribute(suspectContent);
	}

	public String getJs() {
		return encoder.encodeForJavaScript(suspectContent);
	}

	public String getVb() {
		return encoder.encodeForVBScript(suspectContent);
	}

	public String getUrl() {
		try {
			return encoder.encodeForURL(suspectContent);
		} catch (EncodingException e) {
			throw new RuntimeException("Failed url encoding. ", e);
		}
	}

}
