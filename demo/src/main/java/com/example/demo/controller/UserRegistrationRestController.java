package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.db.Userdetail;
import com.example.demo.service.UserService;

@RestController
public class UserRegistrationRestController {
	
	@Autowired
	private UserService userService;
	
	@RequestMapping("/user-registation")
	public String performLocalUserRegistration() {
		return "User Registration reuqest has been prossed.";
	}
	
	
	
	@RequestMapping(value = "/save", method = RequestMethod.GET)
	public Userdetail userDetails() {
		Userdetail userdetail = new Userdetail();
		userdetail.setClientID("test1");
		userdetail.setDeviceID("afdf");
		Userdetail userDetails = userService.save(userdetail);
		return userDetails;
	}
}
