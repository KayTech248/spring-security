package com.taitech.spring_security.repository;

import com.taitech.spring_security.entity.User;
import lombok.Data;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    //Custom method
    public Optional<User> findByEmail(String email);
}
