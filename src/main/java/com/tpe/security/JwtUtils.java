package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.scheduling.support.SimpleTriggerContext;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    //Token oluşturmak için iki bilgiye ihtiyacımız var Secret Key ve Expression(süre)
    private String jwtSecret="sboot";//secret key

    private long jwtExpirationMs =8640000; //24*60*60*1000

//GENERATE JWT TOKEN ****************
    public String generateToke(Authentication authentication){
        //Token üretebilmek için kullanıcıya ulaşmamız lazım
        //Kullanıcıya ulaşabilmek için Authentication objesini parametre olarak vermemiz lazım

        //anlık olarak login işlemini gerçekleştiren kullanıcıya getPrincipal methodu ile erişim sağlıypruz
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        //Methodun dönüş tipini userdetails ile karşılıypruz ama object döndüğü için cast işlemi yapmamız lazım


        //JWT token build ediyor
        return Jwts.builder().
                setSubject(userDetails.getUsername()).
                //Ne zaman creat edilmiş
                setIssuedAt(new Date()).
                //Kullanım süresi //1970 yılına git günümğze gel üzerine bizim belirlediğimiz ex ekle
                setExpiration(new Date(new Date().getTime()+jwtExpirationMs)).
                //Hangi hasleme algoritması kullanılacak// algoritma olarak da benim verdiğim secret key kullan demiş olduk
                signWith(SignatureAlgorithm.ES512,jwtSecret).compact();

    }


    //VALİDATE JWT TOKEN

    //parser()==> tokeni üç parçaya bölüyor
    //setSigningKey secret key ile tersle
    //parseClaimsJws benim terslenmiş tokenin mi kontrol et
    public boolean validateToken(String token){

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token); //gelebilecek exceptionları Sorraund with yaparak otomatik getirdik
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace(); //runtime yerine exception mesajını biz seçmiş olduk
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false;



    }


    // Not: JWT TOKENDEN USERNAME  BILGISINI CEKECEGIZ *****
    public String getUserNameFromJwtToken(String token){

        return Jwts.parser().
                //3 parçaya ayır
                setSigningKey(jwtSecret).
                //secret key ile tersle
                parseClaimsJws(token).
                //parçaları eline al
                getBody().getSubject();
                //parçanın bodysini getir
    }









}
