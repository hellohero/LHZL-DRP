package com.lhzl.drp.filter;

import io.github.pixee.security.Newlines;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CorsFilter implements Filter {

    private String allowOrigin;
    private String allowMethods;
    private String allowCredentials;
    private String allowHeaders;
    private String exposeHeaders;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        allowOrigin = filterConfig.getInitParameter("allowOrigin");
        allowMethods = filterConfig.getInitParameter("allowMethods");
        allowCredentials = filterConfig.getInitParameter("allowCredentials");
        allowHeaders = filterConfig.getInitParameter("allowHeaders");
        exposeHeaders = filterConfig.getInitParameter("exposeHeaders");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (!StringUtils.isEmpty(allowOrigin)) {
            /*List<String> allowOriginList = Arrays.asList(allowOrigin.split(","));
            if (!CollectionUtils.isEmpty(allowOriginList)) {
                String currentOrigin = request.getHeader("Origin");
                if (allowOriginList.contains(currentOrigin)) {
                    response.setHeader("Access-Control-Allow-Origin", currentOrigin);
                }
            }*/
            String currentOrigin = request.getHeader("Origin");
            response.setHeader("Access-Control-Allow-Origin", Newlines.stripAll(currentOrigin));
        }
        if (StringUtils.isEmpty(allowMethods)) {
            response.setHeader("Access-Control-Allow-Methods", Newlines.stripAll(allowMethods));
        }
        if (!StringUtils.isEmpty(allowCredentials)) {
            response.setHeader("Access-Control-Allow-Credentials", Newlines.stripAll(allowCredentials));
        }
        if (!StringUtils.isEmpty(allowHeaders)) {
            response.setHeader("Access-Control-Allow-Headers", Newlines.stripAll(allowHeaders));
        }
        if (!StringUtils.isEmpty(exposeHeaders)) {
            response.setHeader("Access-Control-Expose-Headers", Newlines.stripAll(exposeHeaders));
        }
        chain.doFilter(req, res);
    }

    @Override
    public void destroy() {
    }
}  
