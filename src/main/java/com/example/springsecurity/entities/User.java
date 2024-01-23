package com.example.springsecurity.entities;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Entity
@Table(name = "user")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstname;

    private String secondname;

    private String email;

    // UserDetails interface 에는 getPassword 가 있는데
    // lombok 으로 생성된 이릅과 겹쳐서 @Override method 가 생성되지 않는다.
    private String password;

    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 모든 권한 목록을 넘기는 방식으로 되어 있는데, 이걸 어떻게 활용할 수 있을지는 더 알아볼 필요가 있다.
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        // 일반적으로 계정을 email 을 사용하고 있어서 email 을 반환
        return email;
    }

    /**
     * 아래쪽 코드들은 편의상 모두 true 로 해놓는다.
     * 나중에는 이 코드들을 모두 정상적으로 처리할 수 있게 해야한다.
     */

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
