package net.vidageek.security.safe.el;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import net.vidageek.security.safe.org.owasp.esapi.DefaultEncoder;

/**
 * @author jonasabreu
 * 
 */
final public class SafeSanitizer implements Map<Object, Object> {

	public Sanitizer get(final Object key) {
		if (key == null) {
			return null;
		}
		return new Sanitizer(new DefaultEncoder(), key.toString());
	}

	public boolean isEmpty() {
		return false;
	}

	// Methods to make the compiler happy

	public void clear() {
	}

	public boolean containsKey(final Object key) {
		return true;
	}

	public boolean containsValue(final Object value) {
		return true;
	}

	public Set<java.util.Map.Entry<Object, Object>> entrySet() {
		return null;
	}

	public Set<Object> keySet() {
		return null;
	}

	public Object put(final Object key, final Object value) {
		return null;
	}

	public void putAll(final Map<? extends Object, ? extends Object> m) {
	}

	public Object remove(final Object key) {
		return null;
	}

	public int size() {
		return 1;
	}

	public Collection<Object> values() {
		return null;
	}

}
