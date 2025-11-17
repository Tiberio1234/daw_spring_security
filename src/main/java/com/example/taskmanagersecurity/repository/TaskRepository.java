package com.example.taskmanagersecurity.repository;

import com.example.taskmanagersecurity.model.Task;
import com.example.taskmanagersecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {

    // Find all tasks assigned to a specific user
    List<Task> findByAssignedTo(User user);

    // Find all tasks created by a specific user (for managers/admins)
    List<Task> findByCreatedBy(User user);

    // Find tasks assigned to a user OR created by them (for managers)
    @Query("SELECT t FROM Task t WHERE t.assignedTo = ?1 OR t.createdBy = ?1")
    List<Task> findByAssignedToOrCreatedBy(User user);

    // Count tasks by assigned user
    long countByAssignedTo(User user);

    // Count completed tasks by assigned user
    long countByAssignedToAndCompleted(User user, Boolean completed);
}