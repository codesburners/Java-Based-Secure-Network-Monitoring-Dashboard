package com.networkmonitor.secure_network_monitor.dualsight.repository;

import com.networkmonitor.secure_network_monitor.dualsight.entity.TestCaseEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TestCaseEntityRepository extends JpaRepository<TestCaseEntity, Long> {

    Optional<TestCaseEntity> findByClassName(String className);

    Optional<TestCaseEntity> findByTestNameAndClassName(String testName, String className);

    List<TestCaseEntity> findByTestType(String testType);

    List<TestCaseEntity> findByTargetComponent(String targetComponent);

    List<TestCaseEntity> findAllByOrderByPriorityScoreDesc();

    @Query("SELECT COUNT(tc) FROM TestCaseEntity tc WHERE tc.testType = ?1")
    long countByTestType(String testType);

    @Query("SELECT tc.targetComponent, COUNT(tc) FROM TestCaseEntity tc GROUP BY tc.targetComponent")
    List<Object[]> getTestCountByComponent();

    Optional<TestCaseEntity> findByMethodName(String methodName);
}
