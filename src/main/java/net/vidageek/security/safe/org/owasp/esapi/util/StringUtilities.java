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
package net.vidageek.security.safe.org.owasp.esapi.util;

import java.util.Arrays;

/**
 * The code of this class was extracted from OWASP Enterprise Security API (ESAPI).
 * Svn repo: http://owasp-esapi-java.googlecode.com/svn/trunk
 * Revision: 1222
 * 
 * After extraction, modifications were performed by Jonas Abreu (jonas at vidageek dot net) to fit this project's needs
 */
/**
 * String utilities used in various filters.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class StringUtilities {

	public static char[] union(final char[]... list) {
		StringBuilder sb = new StringBuilder();

		for (char[] characters : list) {
			for (int i = 0; i < list.length; i++) {
				if (!contains(sb, characters[i])) {
					sb.append(list[i]);
				}
			}
		}

		char[] toReturn = new char[sb.length()];
		sb.getChars(0, sb.length(), toReturn, 0);
		Arrays.sort(toReturn);
		return toReturn;
	}

	private static boolean contains(final StringBuilder input, final char c) {
		for (int i = 0; i < input.length(); i++) {
			if (input.charAt(i) == c) {
				return true;
			}
		}
		return false;
	}

}