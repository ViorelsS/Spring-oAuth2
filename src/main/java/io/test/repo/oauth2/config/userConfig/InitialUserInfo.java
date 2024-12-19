package io.test.repo.oauth2.config.userConfig;

import io.test.repo.oauth2.entity.UserInfoEntity;
import io.test.repo.oauth2.repository.UserInfoRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class InitialUserInfo implements CommandLineRunner {

	private final UserInfoRepository userInfoRepo;
	private final PasswordEncoder passwordEncoder;

	public InitialUserInfo(UserInfoRepository userInfoRepo, PasswordEncoder passwordEncoder) {
		this.userInfoRepo = userInfoRepo;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void run(String... args) throws Exception {
		UserInfoEntity manager = new UserInfoEntity();
		manager.setUserName("Manager");
		manager.setPassword(passwordEncoder.encode("password"));
		manager.setRoles("ROLE_MANAGER");
		manager.setEmailId("manager@manager.com");

		UserInfoEntity admin = new UserInfoEntity();
		admin.setUserName("Admin");
		admin.setPassword(passwordEncoder.encode("password"));
		admin.setRoles("ROLE_ADMIN");
		admin.setEmailId("admin@admin.com");

		UserInfoEntity user = new UserInfoEntity();
		user.setUserName("User");
		user.setPassword(passwordEncoder.encode("password"));
		user.setRoles("ROLE_USER");
		user.setEmailId("user@user.com");

		userInfoRepo.saveAll(List.of(manager, admin, user));
	}

}
