package io.test.repo.oauth2.repository;

import io.test.repo.oauth2.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepository extends JpaRepository<UserInfoEntity, Long> {
	Optional<UserInfoEntity> findByEmailId(String emailId);
}
