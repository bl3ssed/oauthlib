package com.raxat.oauthlib.services;

import com.raxat.oauthlib.dto.UserDto;
import com.raxat.oauthlib.models.User;
import com.raxat.oauthlib.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;



@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(UserDto userDto) {
        if (userRepository.findByUsername(userDto.username()) != null) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.findByEmail(userDto.email()) != null) {
            throw new RuntimeException("Email already exists");
        }

        String encodedPassword = passwordEncoder.encode(userDto.password());
        User user = new User(userDto.username(), encodedPassword, userDto.email());
        return userRepository.save(user);
    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }


    public User updateUser(String username, UserDto userDto) {
        User user = getUserByUsername(username);
        if (user == null) {
            throw new RuntimeException("User not found");
        }

        user.setEmail(userDto.email());
        if (!userDto.password().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDto.password()));
        }

        return userRepository.save(user);
    }


    public void deleteUser(String username) {
        User user = getUserByUsername(username);
        if (user == null) {
            throw new RuntimeException("User not found");
        }

        userRepository.delete(user);
    }
    public void deleteUser(long id) {
        User user = getUserById(id);
        if (user == null) {
            throw new RuntimeException("User not found");
        }

        userRepository.delete(user);
    }

}
