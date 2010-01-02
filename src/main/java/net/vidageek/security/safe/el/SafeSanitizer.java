package net.vidageek.security.safe.el;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * @author jonasabreu
 * 
 */
final public class SafeSanitizer implements Map<Object, Object> {

    public Object get(final Object key) {
        return "It work's! " + key.toString();
    }

    public boolean isEmpty() {
        return false;
    }

    // Methods to make the compiler happy

    public void clear() {
    }

    public boolean containsKey(final Object key) {
        return false;
    }

    public boolean containsValue(final Object value) {
        return false;
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
        return 0;
    }

    public Collection<Object> values() {
        return null;
    }

}
