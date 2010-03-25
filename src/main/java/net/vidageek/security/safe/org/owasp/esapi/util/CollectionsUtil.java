/**
 * 
 */
package net.vidageek.security.safe.org.owasp.esapi.util;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 * 
 *         Are these necessary? Are there any libraries or java.lang classes to
 *         take care of the conversions?
 * 
 * 
 */
public class CollectionsUtil {

	private static Set<Character> strToSet(final String str) {
		Set<Character> set;

		if (str == null) {
			return new HashSet<Character>();
		}
		set = new HashSet<Character>(str.length());
		for (int i = 0; i < str.length(); i++) {
			set.add(str.charAt(i));
		}
		return set;
	}

	public static Set<Character> strToUnmodifiableSet(final String str) {
		if (str == null) {
			return Collections.emptySet();
		}
		if (str.length() == 1) {
			return Collections.singleton(str.charAt(0));
		}
		return Collections.unmodifiableSet(strToSet(str));
	}

}
