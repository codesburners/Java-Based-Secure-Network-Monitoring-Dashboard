package com.networkmonitor.secure_network_monitor.dualsight.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity for persisting test case metadata in the database.
 */
@Entity
@Table(name = "dualsight_test_cases")
public class TestCaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "test_name", nullable = false)
    private String testName;

    @Column(name = "class_name", nullable = false)
    private String className;

    @Column(name = "method_name")
    private String methodName;

    @Column(name = "test_type", length = 20)
    private String testType; // BLACK_BOX or WHITE_BOX

    @Column(name = "target_component", length = 100)
    private String targetComponent;

    @Column(name = "priority_level", length = 10)
    private String priorityLevel; // HIGH, MEDIUM, LOW

    @Column(name = "priority_score")
    private Double priorityScore;

    @Column(name = "last_run_status", length = 20)
    private String lastRunStatus;

    @Column(name = "last_run_duration_ms")
    private Long lastRunDurationMs;

    @Column(name = "last_run_timestamp")
    private LocalDateTime lastRunTimestamp;

    @Column(name = "failure_count")
    private Integer failureCount = 0;

    @Column(name = "total_runs")
    private Integer totalRuns = 0;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public TestCaseEntity() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }

    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }

    public String getMethodName() { return methodName; }
    public void setMethodName(String methodName) { this.methodName = methodName; }

    public String getTestType() { return testType; }
    public void setTestType(String testType) { this.testType = testType; }

    public String getTargetComponent() { return targetComponent; }
    public void setTargetComponent(String targetComponent) { this.targetComponent = targetComponent; }

    public String getPriorityLevel() { return priorityLevel; }
    public void setPriorityLevel(String priorityLevel) { this.priorityLevel = priorityLevel; }

    public Double getPriorityScore() { return priorityScore; }
    public void setPriorityScore(Double priorityScore) { this.priorityScore = priorityScore; }

    public String getLastRunStatus() { return lastRunStatus; }
    public void setLastRunStatus(String lastRunStatus) { this.lastRunStatus = lastRunStatus; }

    public Long getLastRunDurationMs() { return lastRunDurationMs; }
    public void setLastRunDurationMs(Long lastRunDurationMs) { this.lastRunDurationMs = lastRunDurationMs; }

    public LocalDateTime getLastRunTimestamp() { return lastRunTimestamp; }
    public void setLastRunTimestamp(LocalDateTime lastRunTimestamp) { this.lastRunTimestamp = lastRunTimestamp; }

    public Integer getFailureCount() { return failureCount; }
    public void setFailureCount(Integer failureCount) { this.failureCount = failureCount; }

    public Integer getTotalRuns() { return totalRuns; }
    public void setTotalRuns(Integer totalRuns) { this.totalRuns = totalRuns; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
