package net.vidageek.security.safe.el;

import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.esapi.Encoder;

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
		String res = new Sanitizer(encoder, "string").toString();
		verify(encoder).encodeForHTML("string");
	}

	@Test
	public void testThatHtmlSanitarizationIsHtml() {
		String res = new Sanitizer(encoder, "string").getHtml();
		verify(encoder).encodeForHTML("string");
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
}
