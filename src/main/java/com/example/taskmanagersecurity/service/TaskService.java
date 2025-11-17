package com.example.taskmanagersecurity.service;

import com.example.taskmanagersecurity.model.Task;
import com.example.taskmanagersecurity.model.User;
import com.example.taskmanagersecurity.repository.TaskRepository;
import com.example.taskmanagersecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
public class TaskService {

    private final TaskRepository taskRepository;
    private final UserRepository userRepository;

    /**
     * Get all tasks visible to the current user based on their role:
     * - ROLE_USER: Only sees tasks assigned to them
     * - ROLE_MANAGER: Sees tasks assigned to them AND tasks they created
     * - ROLE_ADMIN: Sees all tasks in the system
     *
     * Demonstrates: Role-based filtering from presentation Slides 27-28
     */
    @PreAuthorize("isAuthenticated()")
    public List<Task> getTasksForCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        User currentUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (hasRole(auth, "ROLE_ADMIN")) {
            // Admin sees all tasks
            return taskRepository.findAll();
        } else if (hasRole(auth, "ROLE_MANAGER")) {
            // Manager sees tasks assigned to them OR created by them
            return taskRepository.findByAssignedToOrCreatedBy(currentUser);
        } else {
            // Regular user only sees tasks assigned to them
            return taskRepository.findByAssignedTo(currentUser);
        }
    }

    /**
     * Create a task and assign it to a user.
     * - ROLE_MANAGER can create tasks for ROLE_USER
     * - ROLE_ADMIN can create tasks for ROLE_MANAGER and ROLE_USER
     *
     * Demonstrates: @PreAuthorize with SpEL (Slide 29)
     */
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public Task createTask(String title, String description, String assignToUsername) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String creatorUsername = auth.getName();

        User creator = userRepository.findByUsername(creatorUsername)
                .orElseThrow(() -> new RuntimeException("Creator not found"));

        User assignee = userRepository.findByUsername(assignToUsername)
                .orElseThrow(() -> new RuntimeException("User not found: " + assignToUsername));

        // Validate that creator can assign to this user
        validateTaskCreation(creator, assignee);

        Task task = Task.builder()
                .title(title)
                .description(description)
                .assignedTo(assignee)
                .createdBy(creator)
                .completed(false)
                .build();

        return taskRepository.save(task);
    }

    /**
     * Validates role hierarchy for task creation:
     * - MANAGER can only assign to ROLE_USER
     * - ADMIN can assign to ROLE_MANAGER or ROLE_USER
     *
     * Demonstrates: Custom authorization logic (Slides 33-34)
     */
    private void validateTaskCreation(User creator, User assignee) {
        boolean isCreatorManager = creator.getRoles().contains("ROLE_MANAGER");
        boolean isCreatorAdmin = creator.getRoles().contains("ROLE_ADMIN");

        boolean isAssigneeUser = assignee.getRoles().contains("ROLE_USER") &&
                !assignee.getRoles().contains("ROLE_MANAGER") &&
                !assignee.getRoles().contains("ROLE_ADMIN");
        boolean isAssigneeManager = assignee.getRoles().contains("ROLE_MANAGER");

        if (isCreatorManager && !isAssigneeUser) {
            throw new SecurityException("Managers can only create tasks for regular users");
        }

        if (isCreatorAdmin && !(isAssigneeUser || isAssigneeManager)) {
            throw new SecurityException("Admins can only create tasks for users and managers");
        }
    }

    /**
     * Get a specific task by ID.
     * PostAuthorize ensures user can only see tasks they're involved with
     *
     * Demonstrates: @PostAuthorize with SpEL (Slide 30)
     */
    @PostAuthorize("hasRole('ADMIN') or " +
            "returnObject.assignedTo.username == authentication.name or " +
            "returnObject.createdBy.username == authentication.name")
    public Task getTaskById(Long taskId) {
        return taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));
    }

    /**
     * Update task completion status.
     * Only the assignee can mark their task as complete
     *
     * Demonstrates: Custom SpEL method (Slides 31-32)
     */
    @PreAuthorize("@taskSecurityService.canCompleteTask(#taskId, authentication.name)")
    public Task updateTaskCompletion(Long taskId, Boolean completed) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        task.setCompleted(completed);
        if (completed) {
            task.setCompletedAt(LocalDateTime.now());
        } else {
            task.setCompletedAt(null);
        }

        return taskRepository.save(task);
    }

    /**
     * Update task details (title, description).
     * Only the creator can update task details
     */
    @PreAuthorize("hasRole('ADMIN') or @taskSecurityService.isTaskCreator(#taskId, authentication.name)")
    public Task updateTask(Long taskId, String title, String description) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));

        task.setTitle(title);
        task.setDescription(description);

        return taskRepository.save(task);
    }

    /**
     * Delete a task.
     * Only the creator or an admin can delete tasks
     *
     * Demonstrates: Combined SpEL with role and custom method (Slide 33-34)
     */
    @PreAuthorize("hasRole('ADMIN') or @taskSecurityService.isTaskCreator(#taskId, authentication.name)")
    public void deleteTask(Long taskId) {
        Task task = taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found"));
        taskRepository.delete(task);
    }

    /**
     * Get users that the current user can assign tasks to
     * Demonstrates: Role-based business logic
     */
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
    public List<User> getAssignableUsers() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (hasRole(auth, "ROLE_ADMIN")) {
            // Admin can assign to managers and users (not other admins)
            return userRepository.findAll().stream()
                    .filter(u -> !u.getRoles().contains("ROLE_ADMIN"))
                    .toList();
        } else if (hasRole(auth, "ROLE_MANAGER")) {
            // Manager can only assign to regular users
            return userRepository.findAll().stream()
                    .filter(u -> u.getRoles().contains("ROLE_USER") &&
                            !u.getRoles().contains("ROLE_MANAGER") &&
                            !u.getRoles().contains("ROLE_ADMIN"))
                    .toList();
        }

        return List.of();
    }

    /**
     * Get task statistics for current user
     */
    @PreAuthorize("isAuthenticated()")
    public TaskStats getTaskStats() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        User currentUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        long totalTasks;
        long completedTasks;
        long pendingTasks;

        if (hasRole(auth, "ROLE_ADMIN")) {
            totalTasks = taskRepository.count();
            completedTasks = taskRepository.findAll().stream().filter(Task::getCompleted).count();
        } else if (hasRole(auth, "ROLE_MANAGER")) {
            List<Task> managerTasks = taskRepository.findByAssignedToOrCreatedBy(currentUser);
            totalTasks = managerTasks.size();
            completedTasks = managerTasks.stream().filter(Task::getCompleted).count();
        } else {
            totalTasks = taskRepository.countByAssignedTo(currentUser);
            completedTasks = taskRepository.countByAssignedToAndCompleted(currentUser, true);
        }

        pendingTasks = totalTasks - completedTasks;

        return new TaskStats(totalTasks, completedTasks, pendingTasks);
    }

    // ===== Helper methods for backward compatibility =====

    public List<Task> findAll() {
        return taskRepository.findAll();
    }

    public List<Task> findByOwner(User owner) {
        return taskRepository.findByAssignedTo(owner);
    }

    public Optional<Task> findById(Long id) {
        return taskRepository.findById(id);
    }

    public Task updateTask(Task existing, String title, String description) {
        existing.setTitle(title);
        existing.setDescription(description);
        return taskRepository.save(existing);
    }

    public void deleteTask(Task task) {
        taskRepository.delete(task);
    }

    private boolean hasRole(Authentication auth, String role) {
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(role));
    }

    // Statistics record
    public record TaskStats(long total, long completed, long pending) {}
}