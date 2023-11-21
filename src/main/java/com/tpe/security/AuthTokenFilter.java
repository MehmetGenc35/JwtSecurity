package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
//NOT===> Bu classtaki amacımız JWT tabanlı kimlik doğrulaması yapmaktır
    @Autowired
    private JwtUtils jwtUtils;
    //oluşturulan methodları kullanabilmek için DI yaptık

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Requestin içinden gelen tokeni almam lazım
        String jwtToken= parseJwt(request); // artık requestten gelen token elimizde  var
        //Bu token bizim token mi valide etmemiz lazım

        try {
            if(jwtToken!=null && jwtUtils.validateToken(jwtToken)){
                //Kullanıcı valide edildi ama kullanıcıya gönderilmeden contexte gitmesi lazım
                //Jwt içinden username bilgisini çekiyorum

                String userNAme= jwtUtils.getUserNameFromJwtToken(jwtToken);
                //Artık elimizde userName var. Userın ismini getirmemiz lazım
                //User name bilgisi ile userDetail nesnemi getiriyorum
                //UserDetailService DI yapılması lazım

                UserDetails userDetails= userDetailsService.loadUserByUsername(userNAme);
                //Artık elimizde userın userdetail i var.
                //Bunu security contexte göndermemiz lazım
                //Direk yollayamadığımız için
                UsernamePasswordAuthenticationToken authentication=new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);
                //contexte nesnemizi göndermiş olduk.
                //exception fırlama ihtimaline karşı try catch bloğuna alacağız
            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        //Filter Chain ile bu hem requestte hem de repsonse da kullanılsın demiş oluypruz
        filterChain.doFilter(request,response);


    }
    //yardımcı method yazıyoruz
    private String parseJwt(HttpServletRequest request){
        //Bütün header getirme Authorizotion olanı getir
        String header= request.getHeader("Authorization");

        //Gelen token bareer ile mi başlıyor onu kontrol ediyoruz
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            //7. karekterden itibaren  bana döndür demiş olduk Çünkü "Bearer " 6 karakter
            return header.substring(7);
        }
        return null;
    }




}
