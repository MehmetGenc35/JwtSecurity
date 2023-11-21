package com.tpe.domain;

import com.tpe.domain.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

@Entity
@Table(name = "tbl_role")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING) // !!! DB deki tabloda string ifadeler ile kaydedilsin
    @Column(length = 30, nullable = false)
    private UserRole name; // ADMIN - admin - Admin - ADMIN

    @Override
    public String toString() {
        return "Role{" +
                "name=" + name +
                '}';
    }

}
