package io.test.repo.oauth2.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "user_info")
public class UserInfoEntity {

	@Id
	@GeneratedValue
	private Long id;

	@Column(name = "USER_NAME")
	private String userName;

	@Column(nullable = false, name = "EMAIL_ID", unique = true)
	private String emailId;

	@Column(nullable = false, name = "PASSWORD")
	private String password;

	@Column(name = "MOBILE_NUMBER")
	private String mobileNumber;

	@Column(nullable = false, name = "ROLES")
	private String roles;

	@OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<RefreshTokenEntity> refreshTokens;

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEmailId() {
		return emailId;
	}

	public void setEmailId(String emailId) {
		this.emailId = emailId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getMobileNumber() {
		return mobileNumber;
	}

	public void setMobileNumber(String mobileNumber) {
		this.mobileNumber = mobileNumber;
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}
}
