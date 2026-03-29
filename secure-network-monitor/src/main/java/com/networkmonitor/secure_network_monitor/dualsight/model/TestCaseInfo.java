package com.networkmonitor.secure_network_monitor.dualsight.model;

import com.networkmonitor.secure_network_monitor.dualsight.annotation.TestType;

/**
 * Model representing a test case with its metadata and priority information.
 */
public class TestCaseInfo {

    private Long id;
    private String name;
    private String className;
    private String methodName;
    private TestType type;
    private String targetComponent;
    private PriorityLevel priority;
    private String lastRunStatus;
    private Long lastRunDurationMs;
    private Long lastRunTimestamp;
    private double priorityScore;

    public enum PriorityLevel {
        HIGH, MEDIUM, LOW
    }

    // Constructors
    public TestCaseInfo() {}

    public TestCaseInfo(String name, String className, String methodName, TestType type, String targetComponent) {
        this.name = name;
        this.className = className;
        this.methodName = methodName;
        this.type = type;
        this.targetComponent = targetComponent;
        this.priority = PriorityLevel.MEDIUM;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }

    public String getMethodName() { return methodName; }
    public void setMethodName(String methodName) { this.methodName = methodName; }

    public TestType getType() { return type; }
    public void setType(TestType type) { this.type = type; }

    public String getTargetComponent() { return targetComponent; }
    public void setTargetComponent(String targetComponent) { this.targetComponent = targetComponent; }

    public PriorityLevel getPriority() { return priority; }
    public void setPriority(PriorityLevel priority) { this.priority = priority; }

    public String getLastRunStatus() { return lastRunStatus; }
    public void setLastRunStatus(String lastRunStatus) { this.lastRunStatus = lastRunStatus; }

    public Long getLastRunDurationMs() { return lastRunDurationMs; }
    public void setLastRunDurationMs(Long lastRunDurationMs) { this.lastRunDurationMs = lastRunDurationMs; }

    public Long getLastRunTimestamp() { return lastRunTimestamp; }
    public void setLastRunTimestamp(Long lastRunTimestamp) { this.lastRunTimestamp = lastRunTimestamp; }

    public double getPriorityScore() { return priorityScore; }
    public void setPriorityScore(double priorityScore) { this.priorityScore = priorityScore; }
}
