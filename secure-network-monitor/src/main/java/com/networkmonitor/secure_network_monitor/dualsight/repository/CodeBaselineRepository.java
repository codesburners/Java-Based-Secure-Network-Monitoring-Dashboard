package com.networkmonitor.secure_network_monitor.dualsight.repository;

import com.networkmonitor.secure_network_monitor.dualsight.entity.CodeBaselineEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CodeBaselineRepository extends JpaRepository<CodeBaselineEntity, Long> {

    Optional<CodeBaselineEntity> findByFilePath(String filePath);

    Optional<CodeBaselineEntity> findByClassName(String className);

    void deleteByFilePath(String filePath);
}
