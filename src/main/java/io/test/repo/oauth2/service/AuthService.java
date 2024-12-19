package io.test.repo.oauth2.service;

import io.test.repo.oauth2.config.jwtConfig.JwtTokenGenerator;
import io.test.repo.oauth2.dto.AuthResponseDto;
import io.test.repo.oauth2.dto.TokenType;
import io.test.repo.oauth2.dto.UserRegistrationDto;
import io.test.repo.oauth2.entity.RefreshTokenEntity;
import io.test.repo.oauth2.entity.UserInfoEntity;
import io.test.repo.oauth2.repository.RefreshTokenRepository;
import io.test.repo.oauth2.repository.UserInfoRepository;
import io.test.repo.oauth2.util.UserInfoMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

@Service
public class AuthService {
	Logger log = LoggerFactory.getLogger(AuthService.class);

	private final UserInfoRepository userInfoRepo;
	private final JwtTokenGenerator jwtTokenGenerator;
	private final RefreshTokenRepository refreshTokenRepository;
	private final UserInfoMapper userInfoMapper;

	public AuthService(UserInfoRepository userInfoRepo, JwtTokenGenerator jwtTokenGenerator,
			RefreshTokenRepository refreshTokenRepository, UserInfoMapper userInfoMapper) {
		this.userInfoRepo = userInfoRepo;
		this.jwtTokenGenerator = jwtTokenGenerator;
		this.refreshTokenRepository = refreshTokenRepository;
		this.userInfoMapper = userInfoMapper;
	}

	public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
		try {
			var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName()).orElseThrow(() -> {
				log.error("[AuthService:userSignInAuth] User :{} not found", authentication.getName());
				return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
			});

			String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
			String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

			saveUserRefreshToken(userInfoEntity, refreshToken);

			creatRefreshTokenCookie(response, refreshToken);

			log.info("[AuthService:userSignInAuth] dAccess token for user:{}, has been generated",
					userInfoEntity.getUserName());
			return AuthResponseDto.builder().accessToken(accessToken).accessTokenExpiry(15 * 60)
					.userName(userInfoEntity.getUserName()).tokenType(TokenType.Bearer).build();

		} catch (Exception e) {
			log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :" + e.getMessage());
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
		}
	}

	private Cookie creatRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
		Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
		refreshTokenCookie.setHttpOnly(true);
		refreshTokenCookie.setSecure(true);
		refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60);
		response.addCookie(refreshTokenCookie);
		return refreshTokenCookie;
	}

	private void saveUserRefreshToken(UserInfoEntity userInfoEntity, String refreshToken) {
		var refreshTokenEntity = RefreshTokenEntity.builder().user(userInfoEntity).refreshToken(refreshToken).revoked(false)
				.build();
		refreshTokenRepository.save(refreshTokenEntity);
	}

	public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {
		if (!authorizationHeader.startsWith(TokenType.Bearer.name())) {
			return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
		}

		final String refreshToken = authorizationHeader.substring(7);

		//Find refreshToken from database and should not be revoked : Same thing can be done through filter.
		var refreshTokenEntity = refreshTokenRepository.findByRefreshToken(refreshToken)
				.filter(tokens -> !tokens.isRevoked())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));

		UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();

		//Now create the Authentication object
		Authentication authentication = createAuthenticationObject(userInfoEntity);

		//Use the authentication object to generate new accessToken as the Authentication object that we will have may not contain correct role.
		String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

		return AuthResponseDto.builder().accessToken(accessToken).accessTokenExpiry(5 * 60)
				.userName(userInfoEntity.getUserName()).tokenType(TokenType.Bearer).build();
	}

	private static Authentication createAuthenticationObject(UserInfoEntity userInfoEntity) {
		// Extract user details from UserDetailsEntity
		String username = userInfoEntity.getEmailId();
		String password = userInfoEntity.getPassword();
		String roles = userInfoEntity.getRoles();

		// Extract authorities from roles (comma-separated)
		String[] roleArray = roles.split(",");
		GrantedAuthority[] authorities = Arrays.stream(roleArray).map(role -> (GrantedAuthority) role::trim)
				.toArray(GrantedAuthority[]::new);

		return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
	}

	public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,
			HttpServletResponse httpServletResponse) {

		try {
			log.info("[AuthService:registerUser]User Registration Started with :::{}", userRegistrationDto);

			Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
			if (user.isPresent()) {
				throw new Exception("User Already Exist");
			}

			UserInfoEntity userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
			Authentication authentication = createAuthenticationObject(userDetailsEntity);

			// Generate a JWT token
			String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
			String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

			UserInfoEntity savedUserDetails = userInfoRepo.save(userDetailsEntity);
			saveUserRefreshToken(userDetailsEntity, refreshToken);

			creatRefreshTokenCookie(httpServletResponse, refreshToken);

			log.info("[AuthService:registerUser] User:{} Successfully registered", savedUserDetails.getUserName());
			return AuthResponseDto.builder().accessToken(accessToken).accessTokenExpiry(5 * 60)
					.userName(savedUserDetails.getUserName()).tokenType(TokenType.Bearer).build();

		} catch (Exception e) {
			log.error("[AuthService:registerUser]Exception while registering the user due to :" + e.getMessage());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
		}

	}
}
