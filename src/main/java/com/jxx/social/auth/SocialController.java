package com.jxx.social.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@Slf4j
@RestController
@RequiredArgsConstructor
public class SocialController {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @PostMapping("/login/google")
    public void loginUrlGoogle(HttpServletResponse response) throws IOException {
        response.addHeader("content-type","application/x-www-form-urlencoded");
        response.addHeader("client_secret", clientSecret);

        String url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=" + clientId +
                "&redirect_uri=http://localhost:8080/login/oauth2/code/google&response_type=code" +
                "&scope=https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/userinfo.profile";
        response.sendRedirect(url);
    }

    @GetMapping("/login/oauth2/code/google")
    public ResponseEntity<JsonNode> success(@RequestParam("code") String accessCode) throws JsonProcessingException {
        // 액세스 토큰 요청을 위한 매개변수 설정
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.ALL.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", accessCode);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", "http://localhost:8080/login/oauth2/code/google");
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        // Google에 액세스 토큰 요청
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity("https://accounts.google.com/o/oauth2/token", request, String.class);

        // 응답에서 액세스 토큰 추출
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode responseJson = objectMapper.readTree(response.getBody());
        String accessToken = responseJson.get("access_token").asText();

        HttpHeaders userInfoHeaders = new HttpHeaders();
        userInfoHeaders.setBearerAuth(accessToken);
        HttpEntity<?> userInfoRequest = new HttpEntity<>(userInfoHeaders);

        ResponseEntity<String> userInfoResponse = restTemplate.exchange("https://www.googleapis.com/oauth2/v2/userinfo", HttpMethod.GET, userInfoRequest, String.class);
        JsonNode userInfoJson = objectMapper.readTree(userInfoResponse.getBody());

        // 이메일 주소 가져오기
        String email = userInfoJson.get("email").asText();

        return new ResponseEntity<>(userInfoJson, HttpStatus.OK);
    }
}
