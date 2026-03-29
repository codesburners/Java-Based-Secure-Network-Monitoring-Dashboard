package com.networkmonitor.secure_network_monitor.dualsight.repository;

import com.networkmonitor.secure_network_monitor.dualsight.entity.TestResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TestResultEntityRepository extends JpaRepository<TestResultEntity, Long> {

    List<TestResultEntity> findTop50ByOrderByRunTimestampDesc();

    List<TestResultEntity> findByTestCaseName(String testCaseName);

    @Query("SELECT COUNT(tr) FROM TestResultEntity tr WHERE tr.passed = false AND tr.testCaseName = ?1")
    long countFailuresByTestCaseName(String testCaseName);

    @Query("SELECT COUNT(tr) FROM TestResultEntity tr WHERE tr.passed = true")
    long countPassed();

    @Query("SELECT COUNT(tr) FROM TestResultEntity tr WHERE tr.passed = false")
    long countFailed();
}
