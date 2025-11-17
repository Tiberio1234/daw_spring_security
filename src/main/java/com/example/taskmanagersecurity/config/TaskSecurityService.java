package com.example.taskmanagersecurity.config;

import com.example.taskmanagersecurity.model.Task;
import com.example.taskmanagersecurity.repository.TaskRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Custom security service for complex authorization logic in SpEL expressions.
 * Demonstrates Slide 33-34: Custom Authorization Logic
 *
 * These methods are called from @PreAuthorize/@PostAuthorize using SpEL like:
 * @PreAuthorize("@taskSecurityService.canCompleteTask(#taskId, authentication.name)")
 *
 * This approach provides:
 * - Cleaner, more readable security annotations
 * - Reusable authorization logic
 * - Easier testing of security rules
 * - Separation of concerns (security logic vs business logic)
 */
@Service("taskSecurityService")
@RequiredArgsConstructor
public class TaskSecurityService {

    private final TaskRepository taskRepository;

    /**
     * Check if a user can complete/uncomplete a task.
     * Only the assigned user can mark their own tasks as complete.
     *
     * Used in: TaskService.updateTaskCompletion()
     * SpEL: @PreAuthorize("@taskSecurityService.canCompleteTask(#taskId, authentication.name)")
     */
    public boolean canCompleteTask(Long taskId, String username) {
        return taskRepository.findById(taskId)
                .map(task -> task.getAssignedTo().getUsername().equals(username))
                .orElse(false);
    }

    /**
     * Check if a user is the creator of a task.
     * Used for operations where only the creator (or admin) should have access.
     *
     * Used in: TaskService.deleteTask(), TaskService.updateTask()
     * SpEL: @PreAuthorize("@taskSecurityService.isTaskCreator(#taskId, authentication.name)")
     */
    public boolean isTaskCreator(Long taskId, String username) {
        return taskRepository.findById(taskId)
                .map(task -> task.getCreatedBy().getUsername().equals(username))
                .orElse(false);
    }

    /**
     * Check if a user can view a specific task.
     * Users can view tasks if they are:
     * - The assignee (assignedTo)
     * - The creator (createdBy)
     * - An admin (checked separately via hasRole in @PostAuthorize)
     *
     * Used in: TaskService.getTaskById()
     * SpEL: @PreAuthorize("@taskSecurityService.canViewTask(#taskId, authentication.name)")
     */
    public boolean canViewTask(Long taskId, String username) {
        return taskRepository.findById(taskId)
                .map(task -> task.getAssignedTo().getUsername().equals(username) ||
                        task.getCreatedBy().getUsername().equals(username))
                .orElse(false);
    }

    /**
     * Check if a user is assigned to a task.
     * Helper method for ownership checks.
     */
    public boolean isAssignedToTask(Long taskId, String username) {
        return taskRepository.findById(taskId)
                .map(task -> task.getAssignedTo().getUsername().equals(username))
                .orElse(false);
    }
}