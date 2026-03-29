package com.networkmonitor.secure_network_monitor.dualsight.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity for persisting test execution results.
 */
@Entity
@Table(name = "dualsight_test_results")
public class TestResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "test_case_name", nullable = false)
    private String testCaseName;

    @Column(name = "test_class_name")
    private String testClassName;

    @Column(name = "passed")
    private Boolean passed;

    @Column(name = "failure_message", columnDefinition = "TEXT")
    private String failureMessage;

    @Column(name = "execution_time_ms")
    private Long executionTimeMs;

    @Column(name = "run_timestamp")
    private LocalDateTime runTimestamp;

    public TestResultEntity() {
        this.runTimestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTestCaseName() { return testCaseName; }
    public void setTestCaseName(String testCaseName) { this.testCaseName = testCaseName; }

    public String getTestClassName() { return testClassName; }
    public void setTestClassName(String testClassName) { this.testClassName = testClassName; }

    public Boolean getPassed() { return passed; }
    public void setPassed(Boolean passed) { this.passed = passed; }

    public String getFailureMessage() { return failureMessage; }
    public void setFailureMessage(String failureMessage) { this.failureMessage = failureMessage; }

    public Long getExecutionTimeMs() { return executionTimeMs; }
    public void setExecutionTimeMs(Long executionTimeMs) { this.executionTimeMs = executionTimeMs; }

    public LocalDateTime getRunTimestamp() { return runTimestamp; }
    public void setRunTimestamp(LocalDateTime runTimestamp) { this.runTimestamp = runTimestamp; }
}
