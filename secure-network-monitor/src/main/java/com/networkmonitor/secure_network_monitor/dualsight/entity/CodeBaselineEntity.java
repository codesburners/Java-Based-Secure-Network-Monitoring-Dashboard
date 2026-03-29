package com.networkmonitor.secure_network_monitor.dualsight.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity storing Java file AST signatures for change detection comparison.
 * Each record represents a snapshot of a Java file's structure (method signatures).
 */
@Entity
@Table(name = "dualsight_code_baselines")
public class CodeBaselineEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_path", nullable = false)
    private String filePath;

    @Column(name = "class_name", nullable = false)
    private String className;

    /**
     * Stores a hash of the method signatures in the class.
     * Used to detect structural changes.
     */
    @Column(name = "method_signatures_hash", columnDefinition = "TEXT")
    private String methodSignaturesHash;

    /**
     * Comma-separated list of method names for human-readable reference.
     */
    @Column(name = "method_names", columnDefinition = "TEXT")
    private String methodNames;

    @Column(name = "line_count")
    private Integer lineCount;

    @Column(name = "snapshot_timestamp")
    private LocalDateTime snapshotTimestamp;

    public CodeBaselineEntity() {
        this.snapshotTimestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }

    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }

    public String getMethodSignaturesHash() { return methodSignaturesHash; }
    public void setMethodSignaturesHash(String methodSignaturesHash) { this.methodSignaturesHash = methodSignaturesHash; }

    public String getMethodNames() { return methodNames; }
    public void setMethodNames(String methodNames) { this.methodNames = methodNames; }

    public Integer getLineCount() { return lineCount; }
    public void setLineCount(Integer lineCount) { this.lineCount = lineCount; }

    public LocalDateTime getSnapshotTimestamp() { return snapshotTimestamp; }
    public void setSnapshotTimestamp(LocalDateTime snapshotTimestamp) { this.snapshotTimestamp = snapshotTimestamp; }
}
