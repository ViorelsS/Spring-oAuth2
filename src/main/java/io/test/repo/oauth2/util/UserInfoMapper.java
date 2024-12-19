package io.test.repo.oauth2.util;

import io.test.repo.oauth2.dto.UserRegistrationDto;
import io.test.repo.oauth2.entity.UserInfoEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserInfoMapper {
	private final PasswordEncoder passwordEncoder;

	public UserInfoMapper(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	public UserInfoEntity convertToEntity(UserRegistrationDto userRegistrationDto) {
		UserInfoEntity userInfoEntity = new UserInfoEntity();
		userInfoEntity.setUserName(userRegistrationDto.userName());
		userInfoEntity.setEmailId(userRegistrationDto.userEmail());
		userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
		userInfoEntity.setRoles(userRegistrationDto.userRole());
		userInfoEntity.setPassword(passwordEncoder.encode(userRegistrationDto.userPassword()));
		return userInfoEntity;
	}
}
