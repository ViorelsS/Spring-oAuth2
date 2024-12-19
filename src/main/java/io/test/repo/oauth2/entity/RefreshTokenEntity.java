package io.test.repo.oauth2.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

	public RefreshTokenEntity() {
	}

	public RefreshTokenEntity(String refreshToken, boolean revoked, UserInfoEntity user) {
		this.refreshToken = refreshToken;
		this.revoked = revoked;
		this.user = user;
	}

	@Id
	@GeneratedValue
	private Long id;
	@Column(name = "REFRESH_TOKEN", nullable = false, length = 10000)
	private String refreshToken;

	@Column(name = "REVOKED")
	private boolean revoked;

	@ManyToOne
	@JoinColumn(name = "user_id", referencedColumnName = "id")
	private UserInfoEntity user;

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public boolean isRevoked() {
		return revoked;
	}

	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}

	public UserInfoEntity getUser() {
		return user;
	}

	public void setUser(UserInfoEntity user) {
		this.user = user;
	}

	public static RefreshTokenEntity.Builder builder() {
		return new RefreshTokenEntity.Builder();
	}

	public static class Builder {
		private String refreshToken;
		private boolean revoked;
		private UserInfoEntity user;

		public Builder refreshToken(String refreshToken) {
			this.refreshToken = refreshToken;
			return this;
		}

		public Builder revoked(boolean revoked) {
			this.revoked = revoked;
			return this;
		}

		public Builder user(UserInfoEntity user) {
			this.user = user;
			return this;
		}

		public RefreshTokenEntity build() {
			return new RefreshTokenEntity(refreshToken, revoked, user);
		}
	}
}
