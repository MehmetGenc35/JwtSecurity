package com.tpe.dto;
//Login işlemi için yeni bir dto yaptık çünkü lofin olurken bütün bilgileri almıyoruz bazılarını alacağız sadece
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LoginRequest {
    @NotBlank
    private String userName;
    @NotBlank
    private String password;

}
