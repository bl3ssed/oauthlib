package com.raxat.oauthlib.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Setter
@Getter
@AllArgsConstructor
public class JwtToken {
    private String token;
    private String refreshToken;
}
