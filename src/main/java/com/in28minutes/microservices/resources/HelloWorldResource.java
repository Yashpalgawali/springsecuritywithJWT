package com.in28minutes.microservices.resources;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {

	@GetMapping("/hello")
	public String hello()
	{
	
		return "hello World";
	}
}
