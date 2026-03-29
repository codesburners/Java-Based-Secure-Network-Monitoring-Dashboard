package com.networkmonitor.secure_network_monitor.dualsight.service;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.networkmonitor.secure_network_monitor.dualsight.entity.CodeBaselineEntity;
import com.networkmonitor.secure_network_monitor.dualsight.model.CodeChange;
import com.networkmonitor.secure_network_monitor.dualsight.repository.CodeBaselineRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * DualSight Change Detection Service.
 * Uses JavaParser to analyze Java source files and detect structural changes
 * by comparing current AST method signatures against stored baselines.
 */
@Service
public class ChangeDetectionService {

    private static final Logger log = LoggerFactory.getLogger(ChangeDetectionService.class);

    @Autowired
    private CodeBaselineRepository baselineRepository;

    private final JavaParser javaParser = new JavaParser();

    /**
     * Resolves the source root to an absolute path.
     * Tries multiple strategies to find the actual source directory.
     */
    private Path resolveSourceRoot(String sourceRootPath) {
        // 1. Try as-is (could be absolute or relative to CWD)
        Path path = Paths.get(sourceRootPath);
        if (Files.exists(path)) {
            return path.toAbsolutePath().normalize();
        }

        // 2. Try relative to user.dir
        String userDir = System.getProperty("user.dir");
        path = Paths.get(userDir, sourceRootPath);
        if (Files.exists(path)) {
            return path.toAbsolutePath().normalize();
        }

        // 3. Try resolving from the class location (JAR or classes dir)
        try {
            Path classesDir = Paths.get(getClass().getProtectionDomain().getCodeSource().getLocation().toURI());
            // classes dir is typically target/classes, project root is 2 levels up
            Path projectRoot = classesDir.getParent().getParent();
            path = projectRoot.resolve(sourceRootPath);
            if (Files.exists(path)) {
                return path.toAbsolutePath().normalize();
            }
        } catch (Exception e) {
            log.debug("Could not resolve from class location: {}", e.getMessage());
        }

        log.warn("Source root not found with any strategy. Tried: {}, {}/{}, and class-relative",
                sourceRootPath, userDir, sourceRootPath);
        return null;
    }

    /**
     * Scans all Java source files in the project and detects changes
     * compared to the stored baseline.
     *
     * @param sourceRootPath the root path of the Java source files
     * @return list of detected code changes
     */
    public List<CodeChange> detectChanges(String sourceRootPath) {
        List<CodeChange> changes = new ArrayList<>();

        Path sourcePath = resolveSourceRoot(sourceRootPath);
        if (sourcePath == null) {
            log.error("DualSight: Source path could not be resolved: {}", sourceRootPath);
            return changes;
        }

        log.info("DualSight: Scanning for changes in: {}", sourcePath);
        long baselineCount = baselineRepository.count();
        log.info("DualSight: Baseline entries in DB: {}", baselineCount);

        try {
            // Walk through all .java files
            Files.walkFileTree(sourcePath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (file.toString().endsWith(".java") && !file.toString().contains("dualsight")) {
                        try {
                            CodeChange change = analyzeFile(file);
                            if (change != null) {
                                changes.add(change);
                            }
                        } catch (Exception e) {
                            log.error("DualSight: Error analyzing {}: {}", file, e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.error("DualSight: Error scanning source directory: {}", e.getMessage());
        }

        log.info("DualSight: Detected {} changes", changes.size());
        return changes;
    }

    /**
     * Analyzes a single Java file and compares it to the stored baseline.
     *
     * @return CodeChange if changes detected, null if unchanged
     */
    private CodeChange analyzeFile(Path filePath) throws IOException {
        String content = new String(Files.readAllBytes(filePath));
        ParseResult<CompilationUnit> result = javaParser.parse(content);

        if (!result.isSuccessful() || !result.getResult().isPresent()) {
            log.debug("DualSight: Could not parse {}", filePath);
            return null;
        }

        CompilationUnit cu = result.getResult().get();
        // Normalize to absolute path for consistent DB lookups
        String filePathStr = filePath.toAbsolutePath().normalize().toString();
        int lineCount = content.split("\n").length;

        // Extract class and method info from AST
        for (ClassOrInterfaceDeclaration classDecl : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            String className = classDecl.getNameAsString();
            List<String> methodNames = classDecl.getMethods().stream()
                    .map(MethodDeclaration::getNameAsString)
                    .collect(Collectors.toList());

            // Build a signature string from method names + parameter types + body content
            List<String> methodSignatures = classDecl.getMethods().stream()
                    .map(m -> m.getNameAsString() + "(" +
                            m.getParameters().stream()
                                    .map(p -> p.getTypeAsString())
                                    .collect(Collectors.joining(",")) + ")" +
                            ":" + m.getTypeAsString() + " | " + m.getBody().map(Object::toString).orElse(""))
                    .collect(Collectors.toList());

            String signaturesHash = hashSignatures(methodSignatures);

            // Check against baseline
            Optional<CodeBaselineEntity> baseline = baselineRepository.findByFilePath(filePathStr);

            if (baseline.isPresent()) {
                CodeBaselineEntity existing = baseline.get();
                if (!signaturesHash.equals(existing.getMethodSignaturesHash()) || lineCount != existing.getLineCount()) {
                    // Change detected!
                    CodeChange change = new CodeChange(filePathStr, className, CodeChange.ChangeType.MODIFIED);
                    change.setLinesChanged(Math.abs(lineCount - existing.getLineCount()));

                    // Find which methods changed
                    List<String> oldMethods = List.of(existing.getMethodNames().split(","));
                    for (String method : methodNames) {
                        if (!oldMethods.contains(method)) {
                            change.addChangedMethod(method + " (new)");
                        }
                    }
                    for (String oldMethod : oldMethods) {
                        if (!oldMethod.isEmpty() && !methodNames.contains(oldMethod)) {
                            change.addChangedMethod(oldMethod + " (removed)");
                        }
                    }
                    // If signatures changed but method names didn't, methods were internally modified
                    if (change.getChangedMethods().isEmpty()) {
                        for (String method : methodNames) {
                            change.addChangedMethod(method + " (modified)");
                        }
                    }

                    return change;
                }
            } else {
                // New file - no baseline exists
                CodeChange change = new CodeChange(filePathStr, className, CodeChange.ChangeType.ADDED);
                change.setLinesChanged(lineCount);
                change.setChangedMethods(methodNames);
                return change;
            }
        }

        return null;
    }

    /**
     * Updates the baseline snapshot for all Java source files.
     */
    @Transactional
    public int updateBaseline(String sourceRootPath) {
        int filesProcessed = 0;

        Path sourcePath = resolveSourceRoot(sourceRootPath);
        if (sourcePath == null) {
            log.error("DualSight: Cannot update baseline - source path not found: {}", sourceRootPath);
            return 0;
        }

        log.info("DualSight: Updating baseline from: {}", sourcePath);

        try {
            List<Path> javaFiles = new ArrayList<>();
            Files.walkFileTree(sourcePath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (file.toString().endsWith(".java") && !file.toString().contains("dualsight")) {
                        javaFiles.add(file);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });

            for (Path file : javaFiles) {
                try {
                    updateFileBaseline(file);
                    filesProcessed++;
                } catch (Exception e) {
                    System.err.println("DualSight: Error updating baseline for " + file + ": " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("DualSight: Error scanning for baseline update: " + e.getMessage());
        }

        return filesProcessed;
    }

    private void updateFileBaseline(Path filePath) throws IOException {
        String content = new String(Files.readAllBytes(filePath));
        ParseResult<CompilationUnit> result = javaParser.parse(content);

        if (!result.isSuccessful() || !result.getResult().isPresent()) {
            return;
        }

        CompilationUnit cu = result.getResult().get();
        // Normalize to absolute path for consistent DB lookups
        String filePathStr = filePath.toAbsolutePath().normalize().toString();
        int lineCount = content.split("\n").length;

        for (ClassOrInterfaceDeclaration classDecl : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            String className = classDecl.getNameAsString();
            List<String> methodNames = classDecl.getMethods().stream()
                    .map(MethodDeclaration::getNameAsString)
                    .collect(Collectors.toList());

            List<String> methodSignatures = classDecl.getMethods().stream()
                    .map(m -> m.getNameAsString() + "(" +
                            m.getParameters().stream()
                                    .map(p -> p.getTypeAsString())
                                    .collect(Collectors.joining(",")) + ")" +
                            ":" + m.getTypeAsString() + " | " + m.getBody().map(Object::toString).orElse(""))
                    .collect(Collectors.toList());

            String signaturesHash = hashSignatures(methodSignatures);
            String methodNamesStr = String.join(",", methodNames);

            // Upsert baseline
            Optional<CodeBaselineEntity> existing = baselineRepository.findByFilePath(filePathStr);
            CodeBaselineEntity baseline;
            if (existing.isPresent()) {
                baseline = existing.get();
            } else {
                baseline = new CodeBaselineEntity();
                baseline.setFilePath(filePathStr);
            }
            baseline.setClassName(className);
            baseline.setMethodSignaturesHash(signaturesHash);
            baseline.setMethodNames(methodNamesStr);
            baseline.setLineCount(lineCount);

            baselineRepository.save(baseline);
        }
    }

    /**
     * Creates a hash of the method signatures for comparison.
     */
    private String hashSignatures(List<String> signatures) {
        String combined = String.join("|", signatures);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(combined.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return combined.hashCode() + "";
        }
    }
}
