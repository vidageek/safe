package net.vidageek.security.safe.el;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

/**
 * @author jonasabreu
 * 
 */
final public class SafeContextListenerTest {

	@Mock
	private ServletContextEvent event;

	@Mock
	private ServletContext context;

	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
		when(event.getServletContext()).thenReturn(context);
	}

	@Test
	public void testThatRegisterSafeAttributeCleaner() {
		new SafeContextListener().contextInitialized(event);

		verify(context).setAttribute(Mockito.eq("s"), Mockito.any(SafeSanitizer.class));

	}

}
