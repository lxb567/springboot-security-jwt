package fun.pingtan.jwt.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthTokenFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

    @Autowired
    private JwtProvider tokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            String jwt = getJwt(request);
            LOGGER.info("获取到的jwt信息为：{}",jwt);
            if(jwt!=null && tokenProvider.validateJwtToken(jwt)){
                String username = tokenProvider.getUserNameFromJwtToken(jwt);
                //从数据库中获取用户信息，如果没有获取到则抛出异常
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication
                        = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }catch (Exception e){
            LOGGER.error("Can NOT set user authentication -> Message: {}", e);
        }

        filterChain.doFilter(request,response);
    }

    /**
     * 从请求头中获取token字段的值，即jwt的信息
     * @param request
     * @return
     */
    private String getJwt(HttpServletRequest request){
        String authHeader = request.getHeader("token");
        if(authHeader!=null && authHeader.startsWith("lxb")){
            return authHeader.replace("lxb","");
        }
        return null;
    }
}
