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

import java.util.ArrayList;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import net.vidageek.security.safe.org.owasp.esapi.util.EncoderConstants;

/**
 * The Class EncoderTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncoderTest extends TestCase {

	/**
	 * Instantiates a new encoder test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public EncoderTest(final String testName) {
		super(testName);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 */
	@Override
	protected void setUp() throws Exception {
		// none
	}

	/**
	 * {@inheritDoc}s
	 * 
	 * @throws Exception
	 */
	@Override
	protected void tearDown() throws Exception {
		// none
	}

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(EncoderTest.class);
		return suite;
	}

	/**
	 * Test of canonicalize method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws EncodingException
	 */
	public void testCanonicalize() throws EncodingException {
		System.out.println("canonicalize");

		ArrayList<String> list = new ArrayList<String>();
		list.add("HTMLEntityCodec");
		list.add("PercentCodec");
		DefaultEncoder instance = new DefaultEncoder(list);

		// Test null paths
		assertEquals(null, instance.canonicalize(null));
		assertEquals(null, instance.canonicalize(null, true));
		assertEquals(null, instance.canonicalize(null, false));

		// test exception paths
		assertEquals("%", instance.canonicalize("%25", true));
		assertEquals("%", instance.canonicalize("%25", false));

		assertEquals("%", instance.canonicalize("%25"));
		assertEquals("%F", instance.canonicalize("%25F"));
		assertEquals("<", instance.canonicalize("%3c"));
		assertEquals("<", instance.canonicalize("%3C"));
		assertEquals("%X1", instance.canonicalize("%X1"));

		assertEquals("<", instance.canonicalize("&lt"));
		assertEquals("<", instance.canonicalize("&LT"));
		assertEquals("<", instance.canonicalize("&lt;"));
		assertEquals("<", instance.canonicalize("&LT;"));

		assertEquals("%", instance.canonicalize("&#37;"));
		assertEquals("%", instance.canonicalize("&#37"));
		assertEquals("%b", instance.canonicalize("&#37b"));

		assertEquals("<", instance.canonicalize("&#x3c"));
		assertEquals("<", instance.canonicalize("&#x3c;"));
		assertEquals("<", instance.canonicalize("&#x3C"));
		assertEquals("<", instance.canonicalize("&#X3c"));
		assertEquals("<", instance.canonicalize("&#X3C"));
		assertEquals("<", instance.canonicalize("&#X3C;"));

		// percent encoding
		assertEquals("<", instance.canonicalize("%3c"));
		assertEquals("<", instance.canonicalize("%3C"));

		// html entity encoding
		assertEquals("<", instance.canonicalize("&#60"));
		assertEquals("<", instance.canonicalize("&#060"));
		assertEquals("<", instance.canonicalize("&#0060"));
		assertEquals("<", instance.canonicalize("&#00060"));
		assertEquals("<", instance.canonicalize("&#000060"));
		assertEquals("<", instance.canonicalize("&#0000060"));
		assertEquals("<", instance.canonicalize("&#60;"));
		assertEquals("<", instance.canonicalize("&#060;"));
		assertEquals("<", instance.canonicalize("&#0060;"));
		assertEquals("<", instance.canonicalize("&#00060;"));
		assertEquals("<", instance.canonicalize("&#000060;"));
		assertEquals("<", instance.canonicalize("&#0000060;"));
		assertEquals("<", instance.canonicalize("&#x3c"));
		assertEquals("<", instance.canonicalize("&#x03c"));
		assertEquals("<", instance.canonicalize("&#x003c"));
		assertEquals("<", instance.canonicalize("&#x0003c"));
		assertEquals("<", instance.canonicalize("&#x00003c"));
		assertEquals("<", instance.canonicalize("&#x000003c"));
		assertEquals("<", instance.canonicalize("&#x3c;"));
		assertEquals("<", instance.canonicalize("&#x03c;"));
		assertEquals("<", instance.canonicalize("&#x003c;"));
		assertEquals("<", instance.canonicalize("&#x0003c;"));
		assertEquals("<", instance.canonicalize("&#x00003c;"));
		assertEquals("<", instance.canonicalize("&#x000003c;"));
		assertEquals("<", instance.canonicalize("&#X3c"));
		assertEquals("<", instance.canonicalize("&#X03c"));
		assertEquals("<", instance.canonicalize("&#X003c"));
		assertEquals("<", instance.canonicalize("&#X0003c"));
		assertEquals("<", instance.canonicalize("&#X00003c"));
		assertEquals("<", instance.canonicalize("&#X000003c"));
		assertEquals("<", instance.canonicalize("&#X3c;"));
		assertEquals("<", instance.canonicalize("&#X03c;"));
		assertEquals("<", instance.canonicalize("&#X003c;"));
		assertEquals("<", instance.canonicalize("&#X0003c;"));
		assertEquals("<", instance.canonicalize("&#X00003c;"));
		assertEquals("<", instance.canonicalize("&#X000003c;"));
		assertEquals("<", instance.canonicalize("&#x3C"));
		assertEquals("<", instance.canonicalize("&#x03C"));
		assertEquals("<", instance.canonicalize("&#x003C"));
		assertEquals("<", instance.canonicalize("&#x0003C"));
		assertEquals("<", instance.canonicalize("&#x00003C"));
		assertEquals("<", instance.canonicalize("&#x000003C"));
		assertEquals("<", instance.canonicalize("&#x3C;"));
		assertEquals("<", instance.canonicalize("&#x03C;"));
		assertEquals("<", instance.canonicalize("&#x003C;"));
		assertEquals("<", instance.canonicalize("&#x0003C;"));
		assertEquals("<", instance.canonicalize("&#x00003C;"));
		assertEquals("<", instance.canonicalize("&#x000003C;"));
		assertEquals("<", instance.canonicalize("&#X3C"));
		assertEquals("<", instance.canonicalize("&#X03C"));
		assertEquals("<", instance.canonicalize("&#X003C"));
		assertEquals("<", instance.canonicalize("&#X0003C"));
		assertEquals("<", instance.canonicalize("&#X00003C"));
		assertEquals("<", instance.canonicalize("&#X000003C"));
		assertEquals("<", instance.canonicalize("&#X3C;"));
		assertEquals("<", instance.canonicalize("&#X03C;"));
		assertEquals("<", instance.canonicalize("&#X003C;"));
		assertEquals("<", instance.canonicalize("&#X0003C;"));
		assertEquals("<", instance.canonicalize("&#X00003C;"));
		assertEquals("<", instance.canonicalize("&#X000003C;"));
		assertEquals("<", instance.canonicalize("&lt"));
		assertEquals("<", instance.canonicalize("&lT"));
		assertEquals("<", instance.canonicalize("&Lt"));
		assertEquals("<", instance.canonicalize("&LT"));
		assertEquals("<", instance.canonicalize("&lt;"));
		assertEquals("<", instance.canonicalize("&lT;"));
		assertEquals("<", instance.canonicalize("&Lt;"));
		assertEquals("<", instance.canonicalize("&LT;"));

		assertEquals("<script>alert(\"hello\");</script>", instance
				.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
		assertEquals("<script>alert(\"hello\");</script>", instance
				.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E", false));

		// javascript escape syntax
		ArrayList<String> js = new ArrayList<String>();
		js.add("JavaScriptCodec");
		instance = new DefaultEncoder(js);
		System.out.println("JavaScript Decoding");

		assertEquals("\0", instance.canonicalize("\\0"));
		assertEquals("\b", instance.canonicalize("\\b"));
		assertEquals("\t", instance.canonicalize("\\t"));
		assertEquals("\n", instance.canonicalize("\\n"));
		assertEquals("" + (char) 0x0b, instance.canonicalize("\\v"));
		assertEquals("\f", instance.canonicalize("\\f"));
		assertEquals("\r", instance.canonicalize("\\r"));
		assertEquals("\'", instance.canonicalize("\\'"));
		assertEquals("\"", instance.canonicalize("\\\""));
		assertEquals("\\", instance.canonicalize("\\\\"));
		assertEquals("<", instance.canonicalize("\\<"));

		assertEquals("<", instance.canonicalize("\\u003c"));
		assertEquals("<", instance.canonicalize("\\U003c"));
		assertEquals("<", instance.canonicalize("\\u003C"));
		assertEquals("<", instance.canonicalize("\\U003C"));
		assertEquals("<", instance.canonicalize("\\x3c"));
		assertEquals("<", instance.canonicalize("\\X3c"));
		assertEquals("<", instance.canonicalize("\\x3C"));
		assertEquals("<", instance.canonicalize("\\X3C"));

		// css escape syntax
		// be careful because some codecs see \0 as null byte
		ArrayList<String> css = new ArrayList<String>();
		css.add("CSSCodec");
		instance = new DefaultEncoder(css);
		System.out.println("CSS Decoding");
		assertEquals("<", instance.canonicalize("\\3c")); // add strings to
		// prevent null byte
		assertEquals("<", instance.canonicalize("\\03c"));
		assertEquals("<", instance.canonicalize("\\003c"));
		assertEquals("<", instance.canonicalize("\\0003c"));
		assertEquals("<", instance.canonicalize("\\00003c"));
		assertEquals("<", instance.canonicalize("\\3C"));
		assertEquals("<", instance.canonicalize("\\03C"));
		assertEquals("<", instance.canonicalize("\\003C"));
		assertEquals("<", instance.canonicalize("\\0003C"));
		assertEquals("<", instance.canonicalize("\\00003C"));
	}

	/**
	 * Test of canonicalize method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws EncodingException
	 */
	public void testDoubleEncodingCanonicalization() throws EncodingException {
		System.out.println("doubleEncodingCanonicalization");
		Encoder instance = new DefaultEncoder();

		// note these examples use the strict=false flag on canonicalize to
		// allow
		// full decoding without throwing an IntrusionException. Generally, you
		// should use strict mode as allowing double-encoding is an abomination.

		// double encoding examples
		assertEquals("<", instance.canonicalize("&#x26;lt&#59", false)); // double
		// entity
		assertEquals("\\", instance.canonicalize("%255c", false)); // double
		// percent
		assertEquals("%", instance.canonicalize("%2525", false)); // double
		// percent

		// double encoding with multiple schemes example
		assertEquals("<", instance.canonicalize("%26lt%3b", false)); // first
		// entity,
		// then
		// percent
		assertEquals("&", instance.canonicalize("&#x25;26", false)); // first
		// percent,
		// then
		// entity

		// nested encoding examples
		assertEquals("<", instance.canonicalize("%253c", false)); // nested
		// encode %
		// with
		// percent
		assertEquals("<", instance.canonicalize("%%33%63", false)); // nested
		// encode
		// both
		// nibbles
		// with
		// percent
		assertEquals("<", instance.canonicalize("%%33c", false)); // nested
		// encode
		// first
		// nibble
		// with
		// percent
		assertEquals("<", instance.canonicalize("%3%63", false)); // nested
		// encode
		// second
		// nibble
		// with
		// percent
		assertEquals("<", instance.canonicalize("&&#108;t;", false)); // nested
		// encode
		// l
		// with
		// entity
		assertEquals("<", instance.canonicalize("%2&#x35;3c", false)); // triple
		// percent,
		// percent,
		// 5
		// with
		// entity

		// nested encoding with multiple schemes examples
		assertEquals("<", instance.canonicalize("&%6ct;", false)); // nested
		// encode l
		// with
		// percent
		assertEquals("<", instance.canonicalize("%&#x33;c", false)); // nested
		// encode
		// 3
		// with
		// entity

		// multiple encoding tests
		assertEquals("% & <script> <script>", instance
				.canonicalize("%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false));
		assertEquals("< < < < < < <", instance
				.canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false));

		// test strict mode with both mixed and multiple encoding
		try {
			assertEquals("< < < < < < <", instance
					.canonicalize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B"));
		} catch (IntrusionException e) {
			// expected
		}

		try {
			assertEquals("<script", instance.canonicalize("%253Cscript"));
		} catch (IntrusionException e) {
			// expected
		}
		try {
			assertEquals("<script", instance.canonicalize("&#37;3Cscript"));
		} catch (IntrusionException e) {
			// expected
		}
	}

	/**
	 * Test of encodeForHTML method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws Exception
	 */
	public void testEncodeForHTML() throws Exception {
		System.out.println("encodeForHTML");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForHTML(null));
		// test invalid characters are replaced with spaces
		assertEquals("a b c d e f&#x9;g", instance.encodeForHTML("a" + (char) 0 + "b" + (char) 4 + "c" + (char) 128
				+ "d" + (char) 150 + "e" + (char) 159 + "f" + (char) 9 + "g"));

		assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
		assertEquals("&amp;lt&#x3b;script&amp;gt&#x3b;", instance.encodeForHTML("&lt;script&gt;"));
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance
				.encodeForHTML("!@$%()=+{}[]"));
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance
				.encodeForHTML(instance.canonicalize("&#33;&#64;&#36;&#37;&#40;&#41;&#61;&#43;&#123;&#125;&#91;&#93;")));
		assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
		assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
		assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
		assertEquals("" + (char) 12345 + (char) 65533 + (char) 1244, "" + (char) 12345 + (char) 65533 + (char) 1244);
	}

	/**
	 * Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForHTMLAttribute() {
		System.out.println("encodeForHTMLAttribute");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForHTMLAttribute(null));
		assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
		assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
		assertEquals("&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance
				.encodeForHTMLAttribute(" !@$%()=+{}[]"));
	}

	/**
     *
     */
	public void testEncodeForCSS() {
		System.out.println("encodeForCSS");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForCSS(null));
		assertEquals("\\3c script\\3e ", instance.encodeForCSS("<script>"));
		assertEquals("\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d ", instance
				.encodeForCSS("!@$%()=+{}[]"));
	}

	/**
	 * Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForJavascript() {
		System.out.println("encodeForJavascript");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForJavaScript(null));
		assertEquals("\\x3Cscript\\x3E", instance.encodeForJavaScript("<script>"));
		assertEquals(",.\\x2D_\\x20", instance.encodeForJavaScript(",.-_ "));
		assertEquals("\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D", instance
				.encodeForJavaScript("!@$%()=+{}[]"));
		// assertEquals( "\\0", instance.encodeForJavaScript("\0"));
		// assertEquals( "\\b", instance.encodeForJavaScript("\b"));
		// assertEquals( "\\t", instance.encodeForJavaScript("\t"));
		// assertEquals( "\\n", instance.encodeForJavaScript("\n"));
		// assertEquals( "\\v", instance.encodeForJavaScript("" + (char)0x0b));
		// assertEquals( "\\f", instance.encodeForJavaScript("\f"));
		// assertEquals( "\\r", instance.encodeForJavaScript("\r"));
		// assertEquals( "\\'", instance.encodeForJavaScript("\'"));
		// assertEquals( "\\\"", instance.encodeForJavaScript("\""));
		// assertEquals( "\\\\", instance.encodeForJavaScript("\\"));
	}

	/**
     *
     */
	public void testEncodeForVBScript() {
		System.out.println("encodeForVBScript");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForVBScript(null));
		assertEquals("chrw(60)&\"script\"&chrw(62)", instance.encodeForVBScript("<script>"));
		assertEquals(
						"x\"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)",
						instance.encodeForVBScript("x !@$%()=+{}[]"));
		assertEquals("alert\"&chrw(40)&chrw(39)&\"ESAPI\"&chrw(32)&\"test\"&chrw(33)&chrw(39)&chrw(41)", instance
				.encodeForVBScript("alert('ESAPI test!')"));
		assertEquals("jeff.williams\"&chrw(64)&\"aspectsecurity.com", instance
				.encodeForVBScript("jeff.williams@aspectsecurity.com"));
		assertEquals("test\"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&\"test", instance.encodeForVBScript("test <> test"));
	}

	/**
	 * Test of encodeForXPath method, of class org.owasp.esapi.Encoder.
	 */
	public void testEncodeForXPath() {
		System.out.println("encodeForXPath");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForXPath(null));
		assertEquals("&#x27;or 1&#x3d;1", instance.encodeForXPath("'or 1=1"));
	}

	public void testEncodeForXMLNull() {
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForXML(null));
	}

	public void testEncodeForXMLSpace() {
		Encoder instance = new DefaultEncoder();
		assertEquals(" ", instance.encodeForXML(" "));
	}

	public void testEncodeForXMLScript() {
		Encoder instance = new DefaultEncoder();
		assertEquals("&#x3c;script&#x3e;", instance.encodeForXML("<script>"));
	}

	public void testEncodeForXMLImmune() {
		System.out.println("encodeForXML");
		Encoder instance = new DefaultEncoder();
		assertEquals(",.-_", instance.encodeForXML(",.-_"));
	}

	public void testEncodeForXMLSymbol() {
		Encoder instance = new DefaultEncoder();
		assertEquals("&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance
				.encodeForXML("!@$%()=+{}[]"));
	}

	public void testEncodeForXMLPound() {
		System.out.println("encodeForXML");
		Encoder instance = new DefaultEncoder();
		assertEquals("&#xa3;", instance.encodeForXML("\u00A3"));
	}

	public void testEncodeForXMLAttributeNull() {
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForXMLAttribute(null));
	}

	public void testEncodeForXMLAttributeSpace() {
		Encoder instance = new DefaultEncoder();
		assertEquals(" ", instance.encodeForXMLAttribute(" "));
	}

	public void testEncodeForXMLAttributeScript() {
		Encoder instance = new DefaultEncoder();
		assertEquals("&#x3c;script&#x3e;", instance.encodeForXMLAttribute("<script>"));
	}

	public void testEncodeForXMLAttributeImmune() {
		Encoder instance = new DefaultEncoder();
		assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
	}

	public void testEncodeForXMLAttributeSymbol() {
		Encoder instance = new DefaultEncoder();
		assertEquals(" &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;", instance
				.encodeForXMLAttribute(" !@$%()=+{}[]"));
	}

	public void testEncodeForXMLAttributePound() {
		Encoder instance = new DefaultEncoder();
		assertEquals("&#xa3;", instance.encodeForXMLAttribute("\u00A3"));
	}

	/**
	 * Test of encodeForURL method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws Exception
	 */
	public void testEncodeForURL() throws Exception {
		System.out.println("encodeForURL");
		Encoder instance = new DefaultEncoder();
		assertEquals(null, instance.encodeForURL(null));
		assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
	}

	/**
	 * Test of decodeFromURL method, of class org.owasp.esapi.Encoder.
	 * 
	 * @throws Exception
	 */
	public void testDecodeFromURL() throws Exception {
		System.out.println("decodeFromURL");
		Encoder instance = new DefaultEncoder();
		try {
			assertEquals(null, instance.decodeFromURL(null));
			assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
			assertEquals("     ", instance.decodeFromURL("+++++"));
		} catch (Exception e) {
			fail();
		}
		try {
			instance.decodeFromURL("%3xridiculous");
			fail();
		} catch (Exception e) {
			// expected
		}
	}

	public void testCanonicalizePerformance() throws Exception {
		System.out.println("Canonicalization Performance");
		Encoder encoder = new DefaultEncoder();
		int iterations = 100;
		String normal = "The quick brown fox jumped over the lazy dog";

		long start = System.currentTimeMillis();
		String temp = null; // Trade in 1/2 doz warnings in Eclipse for one
		// (never read)
		for (int i = 0; i < iterations; i++) {
			temp = normal;
		}
		long stop = System.currentTimeMillis();
		System.out.println("Normal: " + (stop - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			temp = encoder.canonicalize(normal, false);
		}
		stop = System.currentTimeMillis();
		System.out.println("Normal Loose: " + (stop - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			temp = encoder.canonicalize(normal, true);
		}
		stop = System.currentTimeMillis();
		System.out.println("Normal Strict: " + (stop - start));

		String attack = "%2&#x35;2%3525&#x32;\\u0036lt;\r\n\r\n%&#x%%%3333\\u0033;&%23101;";

		start = System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			temp = attack;
		}
		stop = System.currentTimeMillis();
		System.out.println("Attack: " + (stop - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			temp = encoder.canonicalize(attack, false);
		}
		stop = System.currentTimeMillis();
		System.out.println("Attack Loose: " + (stop - start));

		start = System.currentTimeMillis();
		for (int i = 0; i < iterations; i++) {
			try {
				temp = encoder.canonicalize(attack, true);
			} catch (IntrusionException e) {
				// expected
			}
		}
		stop = System.currentTimeMillis();
		System.out.println("Attack Strict: " + (stop - start));
	}

	public void testConcurrency() {
		System.out.println("Encoder Concurrency");
		for (int i = 0; i < 10; i++) {
			new Thread(new EncoderConcurrencyMock(i)).start();
		}
	}

	/**
	 * A simple class that calls the Encoder to test thread safety
	 */
	public class EncoderConcurrencyMock implements Runnable {
		public int num = 0;

		public EncoderConcurrencyMock(final int num) {
			this.num = num;
		}

		public void run() {
			while (true) {
				String nonce = new DefaultRandomizer().getRandomString(20, EncoderConstants.CHAR_SPECIALS);
				String result = javaScriptEncode(nonce);
				// randomize the threads
				try {
					Thread.sleep(new DefaultRandomizer().getRandomInteger(100, 500));
				} catch (InterruptedException e) {
					// just continue
				}
				assertTrue(result.equals(javaScriptEncode(nonce)));
			}
		}

		public String javaScriptEncode(final String str) {
			DefaultEncoder encoder = new DefaultEncoder();
			return encoder.encodeForJavaScript(str);
		}
	}

}
