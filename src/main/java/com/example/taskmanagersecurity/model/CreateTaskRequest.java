package com.example.taskmanagersecurity.model;

public class CreateTaskRequest {
    private String title;
    private String description;
    private String assignToUsername;

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getAssignToUsername() { return assignToUsername; }
    public void setAssignToUsername(String assignToUsername) {
        this.assignToUsername = assignToUsername;
    }
}
