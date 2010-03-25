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
final public class SanitizerTest {

	@Mock
	private Encoder encoder;

	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
	}

	@Test
	public void testThatDefaultSanitarizationIsHtml() {
		new Sanitizer(encoder, "string").toString();

		verify(encoder).encodeForHTML("string");
	}
}
