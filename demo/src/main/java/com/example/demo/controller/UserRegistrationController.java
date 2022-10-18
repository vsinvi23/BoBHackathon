package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserRegistrationController {
	
	@GetMapping("/show-user-registration-jsp")
	public String showUserRegistrationPage()
	{
		return "user-registartion";
	}
}
