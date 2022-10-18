package com.example.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserRegistrationRestController {
	
	@RequestMapping("/user-registation")
	public String performLocalUserRegistration() {
		
		return "User Registration reuqest has been prossed.";
	}
}
