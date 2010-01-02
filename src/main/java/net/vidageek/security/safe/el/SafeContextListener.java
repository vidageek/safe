package net.vidageek.security.safe.el;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * @author jonasabreu
 * 
 */
final public class SafeContextListener implements ServletContextListener {

    public void contextInitialized(final ServletContextEvent sce) {
        ServletContext context = sce.getServletContext();
        context.setAttribute("safe", new SafeMap());
    }

    public void contextDestroyed(final ServletContextEvent sce) {
    }

}
