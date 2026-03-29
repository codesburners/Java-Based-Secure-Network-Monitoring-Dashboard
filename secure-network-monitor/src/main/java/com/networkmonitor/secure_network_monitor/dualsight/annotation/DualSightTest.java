package com.networkmonitor.secure_network_monitor.dualsight.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * DualSight custom annotation to classify test cases.
 * Applied to test classes to indicate their type and target component.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface DualSightTest {

    /**
     * The type of test: BLACK_BOX or WHITE_BOX
     */
    TestType type();

    /**
     * The target component this test covers (e.g., "AuthController", "DashboardService")
     */
    String component();

    /**
     * Optional description of what this test covers
     */
    String description() default "";
}
