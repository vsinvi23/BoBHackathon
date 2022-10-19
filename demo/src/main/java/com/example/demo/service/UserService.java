package com.example.demo.service;

import java.util.List;

import com.example.demo.db.Userdetail;

public interface UserService {
	public List<Userdetail> getUserDetails();
	
	public Userdetail save(Userdetail userdetail);
}
