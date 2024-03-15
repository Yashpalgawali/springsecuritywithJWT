package com.in28minutes.microservices.resources;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ToDoResource {
 
	private List<Todo> LIST_TODOS = List.of(new Todo("dante"," Learn Microservices"),
			new Todo("nero","Learn AWS"));
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@GetMapping("/todos")
	public List<Todo> retrieveTodos()
	{	LIST_TODOS.add(new Todo("Logan","Learn new"));
		return LIST_TODOS;
	}
	
	@GetMapping("/users/{user}/todos")
	public Todo retrieveTodosForUser(@PathVariable("user") String user)
	{
		Todo tod = null;
		for(int i=0;i<LIST_TODOS.size();i++)
		{
			if(LIST_TODOS.get(i).username().equals(user))
			{
				tod = LIST_TODOS.get(i);
			}
		}
		return tod;
		
	}	
	
	@PostMapping("/users/{user}/todos")
	public void createTodosForUser(@PathVariable("user") String user, @RequestBody Todo todo)
	{
		logger.info("Create {} for {}",todo,user);
		
	}
}
record Todo(String username ,String decription) {}