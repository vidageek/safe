package net.vidageek.security.safe.el;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author jonasabreu
 * 
 */
final public class SafeSanitizerTest {

	@Test
	public void testThatReturnsNullIfKeyIsNull() {
		Assert.assertNull(new SafeSanitizer().get(null));
	}

	@Test
	public void testThatIsEmptyReturnFalse() {
		Assert.assertFalse(new SafeSanitizer().isEmpty());
	}

	@Test
	public void testThatSizeReturnsOne() {
		Assert.assertEquals(1, new SafeSanitizer().size());
	}

	@Test
	public void testThatContainsKeyReturnTrueForAnything() {
		Assert.assertTrue(new SafeSanitizer().containsKey(null));
	}

	@Test
	public void testThatContainsValueReturnTrueForAnything() {
		Assert.assertTrue(new SafeSanitizer().containsValue(null));
	}

}
