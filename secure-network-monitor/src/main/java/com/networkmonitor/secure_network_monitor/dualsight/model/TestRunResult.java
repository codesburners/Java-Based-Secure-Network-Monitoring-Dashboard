package com.networkmonitor.secure_network_monitor.dualsight.model;

import java.time.LocalDateTime;

/**
 * Model representing the result of a single test execution.
 */
public class TestRunResult {

    private Long id;
    private String testCaseName;
    private String testClassName;
    private boolean passed;
    private String failureMessage;
    private long executionTimeMs;
    private LocalDateTime runTimestamp;

    public TestRunResult() {
        this.runTimestamp = LocalDateTime.now();
    }

    public TestRunResult(String testCaseName, String testClassName, boolean passed, long executionTimeMs) {
        this.testCaseName = testCaseName;
        this.testClassName = testClassName;
        this.passed = passed;
        this.executionTimeMs = executionTimeMs;
        this.runTimestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTestCaseName() { return testCaseName; }
    public void setTestCaseName(String testCaseName) { this.testCaseName = testCaseName; }

    public String getTestClassName() { return testClassName; }
    public void setTestClassName(String testClassName) { this.testClassName = testClassName; }

    public boolean isPassed() { return passed; }
    public void setPassed(boolean passed) { this.passed = passed; }

    public String getFailureMessage() { return failureMessage; }
    public void setFailureMessage(String failureMessage) { this.failureMessage = failureMessage; }

    public long getExecutionTimeMs() { return executionTimeMs; }
    public void setExecutionTimeMs(long executionTimeMs) { this.executionTimeMs = executionTimeMs; }

    public LocalDateTime getRunTimestamp() { return runTimestamp; }
    public void setRunTimestamp(LocalDateTime runTimestamp) { this.runTimestamp = runTimestamp; }
}
