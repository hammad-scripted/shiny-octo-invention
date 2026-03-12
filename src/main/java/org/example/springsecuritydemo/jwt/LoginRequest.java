package org.example.springsecuritydemo.jwt;

public class LoginRequest {
    private String username;
    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public LoginRequest(String password, String username) {
        this.password = password;
        this.username = username;
    }
}
