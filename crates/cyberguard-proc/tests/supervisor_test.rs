use cyberguard_proc::{execute_process, ProcessOptions};
use std::time::Duration;

#[tokio::test]
async fn test_successful_command_execution() {
    let options = ProcessOptions::new("echo", vec!["hello".to_string(), "cyberguard".to_string()]);
    let output = execute_process(options).await.expect("Execution failed");

    assert_eq!(output.exit_code, Some(0));
    assert!(output.stdout.contains("hello cyberguard"));
    assert!(!output.truncated);
}

#[tokio::test]
async fn test_failing_command_exit_code() {
    let options = ProcessOptions::new("sh", vec!["-c".to_string(), "exit 42".to_string()]);
    let output = execute_process(options).await.expect("Execution failed");

    assert_eq!(output.exit_code, Some(42));
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
