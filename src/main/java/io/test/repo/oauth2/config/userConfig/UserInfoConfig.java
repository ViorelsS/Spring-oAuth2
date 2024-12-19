package io.test.repo.oauth2.config.userConfig;

import io.test.repo.oauth2.entity.UserInfoEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

public class UserInfoConfig implements UserDetails {
	private final UserInfoEntity userInfoEntity;

	public UserInfoConfig(UserInfoEntity userInfoEntity) {
		this.userInfoEntity = userInfoEntity;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Arrays.stream(userInfoEntity.getRoles().split(",")).map(SimpleGrantedAuthority::new).toList();
	}

	@Override
	public String getPassword() {
		return userInfoEntity.getPassword();
	}

	@Override
	public String getUsername() {
		return userInfoEntity.getEmailId();
	}

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
