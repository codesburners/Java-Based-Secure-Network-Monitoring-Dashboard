package com.networkmonitor.secure_network_monitor.dualsight.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model representing a detected code change in a Java source file.
 */
public class CodeChange {

    private String filePath;
    private String className;
    private List<String> changedMethods;
    private ChangeType changeType;
    private int linesChanged;

    public enum ChangeType {
        ADDED, MODIFIED, DELETED
    }

    public CodeChange() {
        this.changedMethods = new ArrayList<>();
    }

    public CodeChange(String filePath, String className, ChangeType changeType) {
        this.filePath = filePath;
        this.className = className;
        this.changeType = changeType;
        this.changedMethods = new ArrayList<>();
    }

    // Getters and Setters
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }

    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }

    public List<String> getChangedMethods() { return changedMethods; }
    public void setChangedMethods(List<String> changedMethods) { this.changedMethods = changedMethods; }

    public ChangeType getChangeType() { return changeType; }
    public void setChangeType(ChangeType changeType) { this.changeType = changeType; }

    public int getLinesChanged() { return linesChanged; }
    public void setLinesChanged(int linesChanged) { this.linesChanged = linesChanged; }

    public void addChangedMethod(String methodName) {
        this.changedMethods.add(methodName);
    }
}
