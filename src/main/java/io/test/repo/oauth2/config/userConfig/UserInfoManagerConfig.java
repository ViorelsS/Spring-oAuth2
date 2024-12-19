package io.test.repo.oauth2.config.userConfig;

import io.test.repo.oauth2.repository.UserInfoRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserInfoManagerConfig implements UserDetailsService {

	private final UserInfoRepository userInfoRepo;

	public UserInfoManagerConfig(UserInfoRepository userInfoRepo) {
		this.userInfoRepo = userInfoRepo;
	}

	@Override
	public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
		return userInfoRepo.findByEmailId(emailId).map(UserInfoConfig::new)
				.orElseThrow(() -> new UsernameNotFoundException("UserEmail: " + emailId + " does not exist"));
	}
}
