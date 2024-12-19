package io.test.repo.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthResponseDto {

	public AuthResponseDto() {
	}

	public AuthResponseDto(String accessToken, int accessTokenExpiry, TokenType tokenType, String userName) {
		this.accessToken = accessToken;
		this.accessTokenExpiry = accessTokenExpiry;
		this.tokenType = tokenType;
		this.userName = userName;
	}

	@JsonProperty("access_token")
	private String accessToken;

	@JsonProperty("access_token_expiry")
	private int accessTokenExpiry;

	@JsonProperty("token_type")
	private TokenType tokenType;

	@JsonProperty("user_name")
	private String userName;

	private AuthResponseDto(Builder builder) {
		this.accessToken = builder.accessToken;
		this.accessTokenExpiry = builder.accessTokenExpiry;
		this.userName = builder.userName;
		this.tokenType = builder.tokenType;
	}

	// Metodo statico per ottenere il Builder
	public static Builder builder() {
		return new Builder();
	}

	// Classe Builder
	public static class Builder {
		private String accessToken;
		private int accessTokenExpiry;
		private String userName;
		private TokenType tokenType;

		public Builder accessToken(String accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		public Builder accessTokenExpiry(int accessTokenExpiry) {
			this.accessTokenExpiry = accessTokenExpiry;
			return this;
		}

		public Builder userName(String userName) {
			this.userName = userName;
			return this;
		}

		public Builder tokenType(TokenType tokenType) {
			this.tokenType = tokenType;
			return this;
		}

		public AuthResponseDto build() {
			return new AuthResponseDto(this);
		}
	}

}
