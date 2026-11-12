use crate::options::ProcessOptions;
use crate::output::ProcessOutput;
use cyberguard_core::error::{CyberguardError, ProcessError};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Execute a subprocess under strict sandboxing, timeout, and buffer boundaries.
pub async fn execute_process(options: ProcessOptions) -> Result<ProcessOutput, CyberguardError> {
    let start_time = Instant::now();
    let mut cmd = Command::new(&options.command);

    cmd.args(&options.args);

    if let Some(ref cwd) = options.current_dir {
        cmd.current_dir(cwd);
    }

    for (k, v) in &options.envs {
        cmd.env(k, v);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Unix process-group isolation: ensures child and any spawned descendants
    // belong to a separate process group and cannot survive parent timeout.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        CyberguardError::Process(ProcessError::ExecutionFailed {
            command: options.command.clone(),
            source: e,
        })
    })?;

    let child_pid = child.id().map(|id| Pid::from_raw(id as i32));

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let max_bytes = options.max_output_bytes;
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut truncated = false;

    let read_future = async {
        let mut out_chunk = [0u8; 4096];
        let mut err_chunk = [0u8; 4096];

        loop {
            tokio::select! {
                res = async {
                    if let Some(ref mut pipe) = stdout_pipe {
                        pipe.read(&mut out_chunk).await
                    } else {
                        Ok(0)
                    }
                }, if stdout_pipe.is_some() => {
                    match res {
                        Ok(0) => stdout_pipe = None,
                        Ok(n) => {
                            if stdout_buf.len() < max_bytes {
                                let allowed = (max_bytes - stdout_buf.len()).min(n);
                                stdout_buf.extend_from_slice(&out_chunk[..allowed]);
                                if allowed < n {
                                    truncated = true;
                                }
                            } else {
                                truncated = true;
                            }
                        }
                        Err(_) => stdout_pipe = None,
                    }
                }
                res = async {
                    if let Some(ref mut pipe) = stderr_pipe {
                        pipe.read(&mut err_chunk).await
                    } else {
                        Ok(0)
                    }
                }, if stderr_pipe.is_some() => {
                    match res {
                        Ok(0) => stderr_pipe = None,
                        Ok(n) => {
                            if stderr_buf.len() < max_bytes {
                                let allowed = (max_bytes - stderr_buf.len()).min(n);
                                stderr_buf.extend_from_slice(&err_chunk[..allowed]);
                                if allowed < n {
                                    truncated = true;
                                }
                            } else {
                                truncated = true;
                            }
                        }
                        Err(_) => stderr_pipe = None,
                    }
                }
            }

            if stdout_pipe.is_none() && stderr_pipe.is_none() {
                break;
            }
        }

        child.wait().await
    };

    match tokio::time::timeout(options.timeout_duration, read_future).await {
        Ok(wait_result) => {
            let status = wait_result.map_err(|e| {
                CyberguardError::Process(ProcessError::ExecutionFailed {
                    command: options.command.clone(),
                    source: e,
                })
            })?;

            let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
            let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

            Ok(ProcessOutput {
                exit_code: status.code(),
                stdout,
                stderr,
                duration: start_time.elapsed(),
                truncated,
            })
        }
        Err(_) => {
            // Timeout expired: terminate process group
            if let Some(pid) = child_pid {
                #[cfg(unix)]
                {
                    let _ = killpg(pid, Signal::SIGTERM);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    let _ = killpg(pid, Signal::SIGKILL);
                }
            }
            let _ = child.kill().await;

            Err(CyberguardError::Process(ProcessError::Timeout {
                command: options.command,
                duration_secs: options.timeout_duration.as_secs(),
            }))
        }
    }
}
