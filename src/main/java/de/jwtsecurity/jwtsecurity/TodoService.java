package de.jwtsecurity.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;


@RequiredArgsConstructor
@Service
public class TodoService {
    private final TodoRepo todoRepo;

    public List<Todo> getTodos() {
        return todoRepo.findAll();
    }
}
