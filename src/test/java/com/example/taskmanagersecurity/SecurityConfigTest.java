package com.example.taskmanagersecurity;

import com.example.taskmanagersecurity.config.SecurityConfig;
import com.example.taskmanagersecurity.controller.AuthController;
import com.example.taskmanagersecurity.controller.TaskController;
import com.example.taskmanagersecurity.model.Task;
import com.example.taskmanagersecurity.model.User;
import com.example.taskmanagersecurity.service.CustomUserDetailsService;
import com.example.taskmanagersecurity.service.JwtService;
import com.example.taskmanagersecurity.service.TaskService;
import com.example.taskmanagersecurity.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {AuthController.class, TaskController.class})
@Import(SecurityConfig.class)
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CustomUserDetailsService userDetailsService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserService userService;

    @MockBean
    private TaskService taskService;

    @MockBean
    private AuthenticationManager authenticationManager;

    @Test
    void testAuthEndpointsArePublic() throws Exception {

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"username\":\"test\",\"password\":\"test\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testRegisterEndpointIsPublic() throws Exception {

        User mockUser = User.builder()
                .id(1L)
                .username("test")
                .password("encodedPassword")
                .roles(java.util.Set.of("ROLE_USER"))
                .build();

        when(userService.registerUser(anyString(), anyString(), any())).thenReturn(mockUser);

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("{\"username\":\"test\",\"password\":\"test\",\"role\":\"ROLE_USER\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("test"));
    }

    @Test
    void testProtectedEndpointWithoutAuth_Returns403() throws Exception {

        mockMvc.perform(get("/api/tasks"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "testuser", roles = "USER")
    void testProtectedEndpointWithAuth_Returns200() throws Exception {
        when(taskService.getTasksForCurrentUser()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/tasks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @WithMockUser(username = "testuser", roles = "USER")
    void testGetTaskById_WithAuthentication_Returns200() throws Exception {
        User user = User.builder().id(1L).username("testuser").build();
        Task mockTask = Task.builder()
                .id(1L)
                .title("Test Task")
                .description("Description")
                .completed(false)
                .assignedTo(user)
                .createdBy(user)
                .createdAt(LocalDateTime.now())
                .build();

        when(taskService.getTaskById(1L)).thenReturn(mockTask);

        mockMvc.perform(get("/api/tasks/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Test Task"));
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void testCreateTask_WithUserRole_Returns403() throws Exception {

        mockMvc.perform(post("/api/tasks")
                        .contentType("application/json")
                        .content("{\"title\":\"Task\",\"description\":\"Desc\",\"assignToUsername\":\"user\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "manager", roles = "MANAGER")
    void testCreateTask_WithManagerRole_Returns200() throws Exception {
        User manager = User.builder().id(1L).username("manager").build();
        User assignee = User.builder().id(2L).username("user").build();

        Task mockTask = Task.builder()
                .id(1L)
                .title("New Task")
                .description("Description")
                .completed(false)
                .assignedTo(assignee)
                .createdBy(manager)
                .createdAt(LocalDateTime.now())
                .build();

        when(taskService.createTask(anyString(), anyString(), anyString())).thenReturn(mockTask);

        mockMvc.perform(post("/api/tasks")
                        .contentType("application/json")
                        .content("{\"title\":\"New Task\",\"description\":\"Desc\",\"assignToUsername\":\"user\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("New Task"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void testCreateTask_WithAdminRole_Returns200() throws Exception {
        User admin = User.builder().id(1L).username("admin").build();
        User assignee = User.builder().id(2L).username("user").build();

        Task mockTask = Task.builder()
                .id(1L)
                .title("Admin Task")
                .description("Description")
                .completed(false)
                .assignedTo(assignee)
                .createdBy(admin)
                .createdAt(LocalDateTime.now())
                .build();

        when(taskService.createTask(anyString(), anyString(), anyString())).thenReturn(mockTask);

        mockMvc.perform(post("/api/tasks")
                        .contentType("application/json")
                        .content("{\"title\":\"Admin Task\",\"description\":\"Desc\",\"assignToUsername\":\"user\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Admin Task"));
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void testGetAssignableUsers_WithUserRole_Returns403() throws Exception {

        mockMvc.perform(get("/api/tasks/assignable-users"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "manager", roles = "MANAGER")
    void testGetAssignableUsers_WithManagerRole_Returns200() throws Exception {
        when(taskService.getAssignableUsers()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/tasks/assignable-users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void testGetAssignableUsers_WithAdminRole_Returns200() throws Exception {
        when(taskService.getAssignableUsers()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/tasks/assignable-users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void testGetStats_AuthenticatedUser_Returns200() throws Exception {
        TaskService.TaskStats stats = new TaskService.TaskStats(5, 3, 2);
        when(taskService.getTaskStats()).thenReturn(stats);

        mockMvc.perform(get("/api/tasks/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(5))
                .andExpect(jsonPath("$.completed").value(3))
                .andExpect(jsonPath("$.pending").value(2));
    }

    @Test
    void testGetStats_UnauthenticatedUser_Returns403() throws Exception {
        mockMvc.perform(get("/api/tasks/stats"))
                .andExpect(status().isForbidden());
    }

    @Test
    void testCSRFDisabledForStatelessAPI() throws Exception {

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"username\":\"test\",\"password\":\"test\"}"))
                .andExpect(status().isUnauthorized());
    }
}