use cyberguard_proc::{execute_process, ProcessOptions};
use std::time::Duration;

#[tokio::test]
async fn test_successful_command_execution() {
    let options = ProcessOptions::new("echo", vec!["hello".to_string(), "cyberguard".to_string()]);
    let output = execute_process(options).await.expect("Execution failed");

    assert_eq!(output.exit_code, Some(0));
    assert!(output.stdout.contains("hello cyberguard"));
    assert!(!output.truncated);
    assert!(output.is_success());
}

#[tokio::test]
async fn test_failing_command_exit_code() {
    let options = ProcessOptions::new("sh", vec!["-c".to_string(), "exit 42".to_string()]);
    let output = execute_process(options).await.expect("Execution failed");

    assert_eq!(output.exit_code, Some(42));
    assert!(!output.is_success());
}

#[tokio::test]
async fn test_command_timeout_cancellation() {
    let mut options = ProcessOptions::new("sleep", vec!["10".to_string()]);
    options.timeout_duration = Duration::from_millis(300);

    let result = execute_process(options).await;
    assert!(result.is_err());
    match result {
        Err(cyberguard_core::CyberguardError::Process(
            cyberguard_core::ProcessError::Timeout { command, .. },
        )) => {
            assert_eq!(command, "sleep");
        }
        other => panic!("Expected ProcessError::Timeout, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_bounded_output_truncation() {
    // Generate 1000 lines of text
    let mut options = ProcessOptions::new(
        "sh",
        vec![
            "-c".to_string(),
            "for i in $(seq 1 1000); do echo \"CyberGuard line $i\"; done".to_string(),
        ],
    );
    // Limit to 200 bytes
    options.max_output_bytes = 200;

    let output = execute_process(options).await.expect("Execution failed");
    assert!(output.truncated);
    assert!(output.stdout.len() <= 200);
}

#[tokio::test]
async fn test_environment_variables_passed_to_child() {
    let options = ProcessOptions::new(
        "sh",
        vec!["-c".to_string(), "echo $CYBER_CUSTOM_TOKEN".to_string()],
    )
    .with_env("CYBER_CUSTOM_TOKEN", "cg_secret_payload_9988");

    let output = execute_process(options).await.expect("Execution failed");
    assert_eq!(output.exit_code, Some(0));
    assert!(output.stdout.contains("cg_secret_payload_9988"));
}

#[tokio::test]
async fn test_stderr_capture_and_separation() {
    let options = ProcessOptions::new(
        "sh",
        vec![
            "-c".to_string(),
            "echo 'to-stdout'; echo 'to-stderr' >&2".to_string(),
        ],
    );

    let output = execute_process(options).await.expect("Execution failed");
    assert_eq!(output.exit_code, Some(0));
    assert!(output.stdout.contains("to-stdout"));
    assert!(output.stderr.contains("to-stderr"));
}

#[tokio::test]
async fn test_nonexistent_command_returns_execution_failed() {
    let options = ProcessOptions::new("nonexistent_binary_xyz_123", vec![]);
    let result = execute_process(options).await;
    assert!(result.is_err());
    match result {
        Err(cyberguard_core::CyberguardError::Process(
            cyberguard_core::ProcessError::ExecutionFailed { command, .. },
        )) => {
            assert_eq!(command, "nonexistent_binary_xyz_123");
        }
        other => panic!("Expected ProcessError::ExecutionFailed, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_parallel_supervisor_execution() {
    let mut handles = Vec::new();
    for i in 0..8 {
        let handle = tokio::spawn(async move {
            let options = ProcessOptions::new("echo", vec![format!("task_{}", i)]);
            let output = execute_process(options).await.expect("Task failed");
            assert!(output.stdout.contains(&format!("task_{}", i)));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Join failed");
    }
}
