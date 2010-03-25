package net.vidageek.security.safe.org.owasp.esapi.util;

/**
 * Common character classes used for input validation, output encoding,
 * verifying password strength CSRF token generation, generating salts, etc
 * 
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 */
public class EncoderConstants {

	public final static char[] CHAR_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
			'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

	public final static char[] CHAR_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
			'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

	public final static char[] CHAR_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

	public final static char[] CHAR_SPECIALS = { '!', '$', '*', '+', '-', '.', '=', '?', '@', '^', '_', '|', '~' };

	public final static char[] CHAR_LETTERS = StringUtilities.union(CHAR_LOWERS, CHAR_UPPERS);

	public final static char[] CHAR_ALPHANUMERICS = StringUtilities.union(CHAR_LETTERS, CHAR_DIGITS);

}
