package io.test.repo.oauth2.repository;

import io.test.repo.oauth2.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

	Optional<RefreshTokenEntity> findByRefreshToken(String refreshToken);
	
}
