package com.example.demo.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.Topic;

@Controller
public class TopicController 
{
	@RequestMapping("/topics")
	public List<Topic> getAllTopics()
	{
		return Arrays.asList(new Topic [] {
				
				new Topic(1, "Java", "Java Programming Language"),
				new Topic(2, "Spring", "Spring Programming Language"),
				new Topic(3, "SpringBoot", "SpringBoot Programming Language"),
				new Topic(4, "Hibernate", "Hibernate Programming Language")
		});
	}
	
	@GetMapping("/topics1")
	public String getAllTopics1()
	{
		return "index";
	}
}
