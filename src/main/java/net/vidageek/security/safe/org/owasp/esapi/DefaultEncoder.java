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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import net.vidageek.security.safe.org.owasp.esapi.codec.CSSCodec;
import net.vidageek.security.safe.org.owasp.esapi.codec.Codec;
import net.vidageek.security.safe.org.owasp.esapi.codec.HTMLEntityCodec;
import net.vidageek.security.safe.org.owasp.esapi.codec.JavaScriptCodec;
import net.vidageek.security.safe.org.owasp.esapi.codec.PercentCodec;
import net.vidageek.security.safe.org.owasp.esapi.codec.VBScriptCodec;
import net.vidageek.security.safe.org.owasp.esapi.codec.XMLEntityCodec;

import org.apache.log4j.Logger;

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically
 * identified in a list of "immune" characters is encoded.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class DefaultEncoder implements Encoder {

	private final List<Codec> codecs = new ArrayList<Codec>();
	private final HTMLEntityCodec htmlCodec = new HTMLEntityCodec();
	private final XMLEntityCodec xmlCodec = new XMLEntityCodec();
	private final PercentCodec percentCodec = new PercentCodec();
	private final JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
	private final VBScriptCodec vbScriptCodec = new VBScriptCodec();
	private final CSSCodec cssCodec = new CSSCodec();

	private final Logger logger = Logger.getLogger(DefaultEncoder.class);

	/**
	 * Character sets that define characters (in addition to alphanumerics) that
	 * are immune from encoding in various formats
	 */
	private final static char[] IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_CSS = {};
	private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
	private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '_' };
	private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
	private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
	private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };

	/**
	 * Instantiates a new DefaultEncoder
	 */
	public DefaultEncoder() {
		codecs.add(htmlCodec);
		codecs.add(percentCodec);
		codecs.add(javaScriptCodec);
	}

	public DefaultEncoder(final List<String> codecNames) {
		for (String clazz : codecNames) {
			try {
				if (clazz.indexOf('.') == -1) {
					clazz = "net.vidageek.security.safe.org.owasp.esapi.codec." + clazz;
				}
				codecs.add((Codec) Class.forName(clazz).newInstance());
			} catch (Exception e) {
				logger.warn("Codec " + clazz + " listed in ESAPI.properties not on classpath");
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String canonicalize(final String input) {
		if (input == null) {
			return null;
		}
		return canonicalize(input, true);
	}

	/**
	 * {@inheritDoc}
	 */
	public String canonicalize(final String input, final boolean strict) {
		if (input == null) {
			return null;
		}

		String working = input;
		Codec codecFound = null;
		int mixedCount = 1;
		int foundCount = 0;
		boolean clean = false;
		while (!clean) {
			clean = true;

			// try each codec and keep track of which ones work
			Iterator<Codec> i = codecs.iterator();
			while (i.hasNext()) {
				Codec codec = i.next();
				String old = working;
				working = codec.decode(working);
				if (!old.equals(working)) {
					if ((codecFound != null) && (codecFound != codec)) {
						mixedCount++;
					}
					codecFound = codec;
					if (clean) {
						foundCount++;
					}
					clean = false;
				}
			}
		}

		// do strict tests and handle if any mixed, multiple, nested encoding
		// were found
		if ((foundCount >= 2) && (mixedCount > 1)) {
			if (strict) {
				throw new IntrusionException("Multiple (" + foundCount + "x) and mixed encoding (" + mixedCount
						+ "x) detected in " + input);
			} else {
				logger.warn("Multiple (" + foundCount + "x) and mixed encoding (" + mixedCount + "x) detected in "
						+ input);
			}
		} else if (foundCount >= 2) {
			if (strict) {
				throw new IntrusionException("Multiple (" + foundCount + "x) encoding detected in " + input);
			} else {
				logger.warn("Multiple (" + foundCount + "x) encoding detected in " + input);
			}
		} else if (mixedCount > 1) {
			if (strict) {
				throw new IntrusionException("Mixed encoding (" + mixedCount + "x) detected in " + input);
			} else {
				logger.warn("Mixed encoding (" + mixedCount + "x) detected in " + input);
			}
		}
		return working;
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForHTML(final String input) {
		if (input == null) {
			return null;
		}
		return htmlCodec.encode(IMMUNE_HTML, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String decodeForHTML(final String input) {

		if (input == null) {
			return null;
		}
		return htmlCodec.decode(input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForHTMLAttribute(final String input) {
		if (input == null) {
			return null;
		}
		return htmlCodec.encode(IMMUNE_HTMLATTR, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForCSS(final String input) {
		if (input == null) {
			return null;
		}
		return cssCodec.encode(IMMUNE_CSS, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForJavaScript(final String input) {
		if (input == null) {
			return null;
		}
		return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForVBScript(final String input) {
		if (input == null) {
			return null;
		}
		return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXPath(final String input) {
		if (input == null) {
			return null;
		}
		return htmlCodec.encode(IMMUNE_XPATH, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXML(final String input) {
		if (input == null) {
			return null;
		}
		return xmlCodec.encode(IMMUNE_XML, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForXMLAttribute(final String input) {
		if (input == null) {
			return null;
		}
		return xmlCodec.encode(IMMUNE_XMLATTR, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeForURL(final String input) throws EncodingException {
		if (input == null) {
			return null;
		}
		try {
			return URLEncoder.encode(input, "UTF-8");
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Character encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Problem URL encoding input", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String decodeFromURL(final String input) throws EncodingException {
		if (input == null) {
			return null;
		}
		String canonical = canonicalize(input);
		try {
			return URLDecoder.decode(canonical, "UTF-8");
		} catch (UnsupportedEncodingException ex) {
			throw new EncodingException("Character encoding not supported", ex);
		} catch (Exception e) {
			throw new EncodingException("Problem URL decoding input", e);
		}
	}

}
