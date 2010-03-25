package net.vidageek.security.safe.el;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import junit.framework.Assert;
import net.vidageek.security.safe.org.owasp.esapi.Encoder;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * @author jonasabreu
 * 
 */
@SuppressWarnings("unused")
final public class SanitizerTest {

	@Mock
	private Encoder encoder;

	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testThatDefaultSanitarizationIsHtml() {
		when(encoder.canonicalize("string")).thenReturn("string");

		String res = new Sanitizer(encoder, "string").toString();

		verify(encoder).encodeForHTML("string");
		verify(encoder).canonicalize("string");
	}

	@Test
	public void testThatHtmlSanitarizationIsHtml() {
		when(encoder.canonicalize("string")).thenReturn("string");

		String res = new Sanitizer(encoder, "string").getHtml();

		verify(encoder).encodeForHTML("string");
		verify(encoder).canonicalize("string");
	}

	@Test
	public void testThatCssSanitarizationIsCss() {
		String res = new Sanitizer(encoder, "string").getCss();
		verify(encoder).encodeForCSS("string");
	}

	@Test
	public void testThatAttrSanitarizationIsHtmlAttribute() {
		String res = new Sanitizer(encoder, "string").getAttr();
		verify(encoder).encodeForHTMLAttribute("string");
	}

	@Test
	public void testThatJSSanitarizationIsJavascript() {
		String res = new Sanitizer(encoder, "string").getJs();
		verify(encoder).encodeForJavaScript("string");
	}

	@Test
	public void testThatVBScriptSanitarizationIsVBscript() {
		String res = new Sanitizer(encoder, "string").getVb();
		verify(encoder).encodeForVBScript("string");
	}

	@Test
	public void testThatUrlSanitarizationIsUrl() throws Throwable {
		String res = new Sanitizer(encoder, "string").getUrl();
		verify(encoder).encodeForURL("string");
	}

	@Test
	public void testThatDoesNotRencodeHtmlEntities() {
		Assert.assertEquals("&atilde;", new Sanitizer(new Encoder(), "&atilde;").getHtml());
	}
}
