package com.example.taskmanagersecurity.controller;

import com.example.taskmanagersecurity.model.CreateTaskRequest;
import com.example.taskmanagersecurity.model.Task;
import com.example.taskmanagersecurity.model.UpdateTaskRequest;
import com.example.taskmanagersecurity.model.User;
import com.example.taskmanagersecurity.service.TaskService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * REST Controller demonstrating Spring Security features:
 * - URL-level authorization with @PreAuthorize (Slides 27-28)
 * - Method-level security delegated to service layer
 * - DTO pattern for API responses
 */
@RestController
@RequestMapping("/api/tasks")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class TaskController {

    private final TaskService taskService;

    /**
     * Get all tasks for the current user based on their role.
     * Authorization logic in service layer determines visibility.
     *
     * Demonstrates: Role-based data filtering (Slide 27-28)
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<TaskDTO>> getTasks() {
        List<Task> tasks = taskService.getTasksForCurrentUser();
        List<TaskDTO> taskDTOs = tasks.stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(taskDTOs);
    }

    /**
     * Get a specific task by ID.
     * @PostAuthorize in service layer verifies access.
     *
     * Demonstrates: @PostAuthorize for ownership checks (Slide 30)
     */
    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<TaskDTO> getTask(@PathVariable Long id) {
        try {
            Task task = taskService.getTaskById(id);
            return ResponseEntity.ok(toDTO(task));
        } catch (Exception e) {
            return ResponseEntity.status(403).build();
        }
    }

    /**
     * Create a new task and assign it to a user.
     * Only MANAGER and ADMIN roles can create tasks.
     * Role hierarchy validation in service layer.
     *
     * Demonstrates: @PreAuthorize with role checks (Slide 29)
     */
    @PostMapping
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<?> createTask(@RequestBody CreateTaskRequest request) {
        try {
            Task task = taskService.createTask(
                    request.getTitle(),
                    request.getDescription(),
                    request.getAssignToUsername()
            );
            return ResponseEntity.ok(toDTO(task));
        } catch (SecurityException e) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", e.getMessage()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Update task completion status.
     * Uses custom SpEL to verify only assignee can complete.
     *
     * Demonstrates: Custom SpEL authorization (Slides 31-32)
     */
    @PatchMapping("/{id}/complete")
    public ResponseEntity<?> updateCompletion(
            @PathVariable Long id,
            @RequestBody Map<String, Boolean> body) {
        try {
            Boolean completed = body.get("completed");
            Task task = taskService.updateTaskCompletion(id, completed);
            return ResponseEntity.ok(toDTO(task));
        } catch (Exception e) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Access denied: " + e.getMessage()));
        }
    }

    /**
     * Update task details (title, description).
     * Only creator or admin can update.
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateTask(
            @PathVariable Long id,
            @RequestBody UpdateTaskRequest request) {
        try {
            Task task = taskService.updateTask(id, request.getTitle(), request.getDescription());
            return ResponseEntity.ok(toDTO(task));
        } catch (Exception e) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Access denied: " + e.getMessage()));
        }
    }

    /**
     * Delete a task.
     * Only creator or admin can delete.
     *
     * Demonstrates: Combined SpEL with custom method (Slides 33-34)
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteTask(@PathVariable Long id) {
        try {
            taskService.deleteTask(id);
            return ResponseEntity.ok(Map.of("message", "Task deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Access denied: " + e.getMessage()));
        }
    }

    /**
     * Get list of users that current user can assign tasks to.
     * Role-based filtering in service layer.
     *
     * Demonstrates: Role hierarchy enforcement
     */
    @GetMapping("/assignable-users")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public ResponseEntity<List<UserDTO>> getAssignableUsers() {
        List<User> users = taskService.getAssignableUsers();
        List<UserDTO> userDTOs = users.stream()
                .map(u -> new UserDTO(u.getId(), u.getUsername(), u.getRoles()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDTOs);
    }

    /**
     * Get task statistics for current user.
     * Statistics calculated based on role permissions.
     */
    @GetMapping("/stats")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<TaskService.TaskStats> getStats() {
        return ResponseEntity.ok(taskService.getTaskStats());
    }

    // Helper method to convert Task entity to DTO
    private TaskDTO toDTO(Task task) {
        return new TaskDTO(
                task.getId(),
                task.getTitle(),
                task.getDescription(),
                task.getCompleted(),
                task.getAssignedTo().getUsername(),
                task.getCreatedBy().getUsername(),
                task.getCreatedAt().toString(),
                task.getCompletedAt() != null ? task.getCompletedAt().toString() : null
        );
    }


    /**
     * Response DTO for task data
     */
    public record TaskDTO(
            Long id,
            String title,
            String description,
            Boolean completed,
            String assignedTo,      // assignedTo username
            String createdBy,       // creator username
            String createdAt,
            String completedAt
    ) {}

    /**
     * Response DTO for user data
     */
    public record UserDTO(
            Long id,
            String username,
            java.util.Set<String> roles
    ) {}
}