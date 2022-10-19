package com.example.demo.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.db.UserRepository;
import com.example.demo.db.Userdetail;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepository userRepository;

	public List<Userdetail> getUserDetails() {
		return userRepository.findAll();
	}
	public Userdetail save(Userdetail userdetail) {
		return userRepository.saveAndFlush(userdetail);
	}

}