package de.jwtsecurity.jwtsecurity;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface TodoRepo extends MongoRepository<Todo, String> {
}
