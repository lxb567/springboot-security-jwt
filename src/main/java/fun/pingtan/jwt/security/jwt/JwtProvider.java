package fun.pingtan.jwt.security.jwt;

import fun.pingtan.jwt.security.services.UserPrinciple;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * 工具类
 * 解析jwt，生成jwt，验证jwt
 */
@Component
public class JwtProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${lxb.jwtSecret}")
    private String jwtSecret;

    @Value("${lxb.jwtExpiration}")
    private int jwtExpiration;

    /**
     * 生成jwt信息
     * @param authentication
     * @return
     */
    public String generateJwtToken(Authentication authentication){
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrinciple.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime()+jwtExpiration*1000))
                .signWith(SignatureAlgorithm.HS512,jwtSecret)
                .compact();
    }

    /**
     * 验证签名
     * @param authToken
     * @return
     */
    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        }catch (SignatureException e){
            LOGGER.error("签名不正确 -> Message:{}",e);
        }catch (MalformedJwtException e){
            LOGGER.error("鉴权信息token不正确 -> Message:{}",e);
        }catch (ExpiredJwtException e){
            LOGGER.error("鉴权信息已过期 -> Message:{}",e);
        }catch (UnsupportedJwtException e){
            LOGGER.error("不支持的token鉴权 -> Message:{}",e);
        }catch (IllegalArgumentException e){
            LOGGER.error("鉴权中的声明信息为空 -> Message:{}",e);
        }

        return false;
    }

    /**
     * 解析jwt获取里面的用户信息，即用户名
     * @param token
     * @return
     */
    public String getUserNameFromJwtToken(String token){
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
