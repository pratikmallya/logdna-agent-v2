use assert_cmd::prelude::*;
use predicates::prelude::*;

use tempfile::tempdir;

use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use std::thread;

use logdna_mock_ingester::https_ingester;

use rcgen::generate_simple_self_signed;
use rustls::internal::pemfile;

#[test]
#[cfg_attr(not(feature = "integration_tests"), ignore)]
fn api_key_missing() {
    let mut cmd = Command::cargo_bin("logdna-agent").unwrap();
    cmd.env_clear()
        .env("RUST_LOG", "debug")
        .assert()
        .stderr(predicate::str::contains(
            "config error: http.ingestion_key is missing",
        ))
        .failure();
}

#[test]
#[cfg_attr(not(feature = "integration_tests"), ignore)]
fn api_key_present() {
    let _ = env_logger::Builder::from_default_env().try_init();
    let dir = tempdir().expect("Couldn't create temp dir...");

    let mut cmd = Command::cargo_bin("logdna-agent").unwrap();

    let dir_path = format!("{}/", dir.path().to_str().unwrap());

    let before_file_path = dir.path().join("before.log");
    let mut file = File::create(&before_file_path).expect("Couldn't create temp log file...");

    let ingestion_key =
        std::env::var("LOGDNA_INGESTION_KEY").expect("LOGDNA_INGESTION_KEY env var not set");
    assert!(ingestion_key != "");
    let agent = cmd
        .env_clear()
        .env("RUST_LOG", "debug")
        .env("RUST_BACKTRACE", "full")
        .env("LOGDNA_LOG_DIRS", &dir_path)
        .env(
            "LOGDNA_HOST",
            std::env::var("LOGDNA_HOST").expect("LOGDNA_HOST env var not set"),
        )
        .env("LOGDNA_INGESTION_KEY", ingestion_key)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut handle = agent.spawn().expect("Failed to start agent");
    // Dump the agent's stdout
    // TODO: assert that it's successfully uploaded

    thread::sleep(std::time::Duration::from_secs(1));

    let log_lines = "This is a test log line\nLook at me, another test log line\nMore log lines....\nAnother log line!";

    writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
    file.sync_all().unwrap();
    thread::sleep(std::time::Duration::from_secs(1));

    let test_file_path = dir.path().join("test.log");
    let mut file = File::create(&test_file_path).expect("Couldn't create temp log file...");

    writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
    file.sync_all().unwrap();
    thread::sleep(std::time::Duration::from_secs(1));

    let test1_file_path = dir.path().join("test1.log");
    let mut file = File::create(&test1_file_path).expect("Couldn't create temp log file...");

    writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
    file.sync_all().unwrap();
    thread::sleep(std::time::Duration::from_secs(1));

    handle.kill().unwrap();
    let mut output = String::new();

    let stderr_ref = handle.stderr.as_mut().unwrap();
    stderr_ref.read_to_string(&mut output).unwrap();

    // Check that the agent logs that it has sent lines from each file
    assert!(predicate::str::contains(&format!(
        "watching \"{}\"",
        before_file_path.to_str().unwrap()
    ))
    .eval(&output));
    assert!(predicate::str::contains(&format!(
        "tailer sendings lines for [\"{}\"]",
        before_file_path.to_str().unwrap()
    ))
    .eval(&output));

    assert!(predicate::str::contains(&format!(
        "watching \"{}\"",
        test_file_path.to_str().unwrap()
    ))
    .eval(&output));
    assert!(predicate::str::contains(&format!(
        "tailer sendings lines for [\"{}\"]",
        test_file_path.to_str().unwrap()
    ))
    .eval(&output));

    assert!(predicate::str::contains(&format!(
        "watching \"{}\"",
        test1_file_path.to_str().unwrap()
    ))
    .eval(&output));
    assert!(predicate::str::contains(&format!(
        "tailer sendings lines for [\"{}\"]",
        test1_file_path.to_str().unwrap()
    ))
    .eval(&output));

    handle.wait().unwrap();
}

#[test]
#[cfg_attr(not(feature = "integration_tests"), ignore)]
fn lookback_start_lines_are_delivered() {
    let _ = env_logger::Builder::from_default_env().try_init();
    let subject_alt_names = vec!["logdna.com".to_string(), "localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    // The certificate is now valid for localhost and the domain "hello.world.example"
    let certs =
        pemfile::certs(&mut cert.serialize_pem().unwrap().as_bytes()).expect("couldn't load certs");
    let key = pemfile::pkcs8_private_keys(&mut cert.serialize_private_key_pem().as_bytes())
        .expect("couldn't load rsa_private_key");
    let addr = "0.0.0.0:1337".parse().unwrap();

    let mut cert_file = tempfile::NamedTempFile::new().expect("Couldn't create cert file");
    cert_file
        .write_all(cert.serialize_pem().unwrap().as_bytes())
        .expect("Couldn't write cert file");

    let (server, received, shutdown_handle) = https_ingester(addr, certs, key[0].clone());

    let dir = tempdir().expect("Couldn't create temp dir...");

    let mut cmd = Command::cargo_bin("logdna-agent").unwrap();

    let dir_path = format!("{}/", dir.path().to_str().unwrap());

    let agent = cmd
        .env_clear()
        .env("RUST_LOG", "debug")
        .env("RUST_BACKTRACE", "full")
        .env("SSL_CERT_FILE", cert_file.path().to_str().unwrap())
        .env("LOGDNA_LOG_DIRS", &dir_path)
        .env("LOGDNA_HOST", "localhost:1337")
        .env("LOGDNA_LOOKBACK", "start")
        .env("LOGDNA_INGESTION_KEY", "1234")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let log_lines = "This is a test log line";

    let file_path = dir.path().join("test.log");
    let mut file = File::create(&file_path).expect("Couldn't create temp log file...");

    // Enough bytes to get past the lookback threshold
    let line_write_count = (8192 / (log_lines.as_bytes().len() + 1)) + 1;

    (0..line_write_count)
        .for_each(|_| writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file..."));
    file.sync_all().expect("Failed to sync file");

    let mut handle = agent.spawn().expect("Failed to start agent");
    // Dump the agent's stdout
    // TODO: assert that it's successfully uploaded

    thread::sleep(std::time::Duration::from_secs(1));

    tokio_test::block_on(async {
        let (line_count, _, server) = tokio::join!(
            async {
                tokio::time::delay_for(tokio::time::Duration::from_millis(5000)).await;
                let line_count = received
                    .lock()
                    .await
                    .get(file_path.to_str().unwrap())
                    .unwrap()
                    .0
                    .load(std::sync::atomic::Ordering::Relaxed);
                shutdown_handle();
                let mut output = String::new();

                handle.kill().unwrap();
                let stderr_ref = handle.stderr.as_mut().unwrap();

                stderr_ref.read_to_string(&mut output).unwrap();
                handle.wait().unwrap();
                line_count
            },
            async move {
                tokio::time::delay_for(tokio::time::Duration::from_millis(500)).await;
                (0..5).for_each(|_| {
                    writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
                    file.sync_all().expect("Failed to sync file");
                });
                tokio::time::delay_for(tokio::time::Duration::from_millis(500)).await;
                // Hack to drive stream forward
                writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
                file.sync_all().expect("Failed to sync file");
            },
            server
        );
        server.unwrap();
        assert_eq!(line_count, line_write_count + 5);
    });
}

#[test]
#[cfg_attr(not(feature = "integration_tests"), ignore)]
fn lookback_none_lines_are_delivered() {
    let _ = env_logger::Builder::from_default_env().try_init();

    let subject_alt_names = vec!["logdna.com".to_string(), "localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    // The certificate is now valid for localhost and the domain "hello.world.example"
    let certs =
        pemfile::certs(&mut cert.serialize_pem().unwrap().as_bytes()).expect("couldn't load certs");
    let key = pemfile::pkcs8_private_keys(&mut cert.serialize_private_key_pem().as_bytes())
        .expect("couldn't load rsa_private_key");
    let addr = "0.0.0.0:1338".parse().unwrap();

    let mut cert_file = tempfile::NamedTempFile::new().expect("Couldn't create cert file");
    cert_file
        .write_all(cert.serialize_pem().unwrap().as_bytes())
        .expect("Couldn't write cert file");

    let (server, received, shutdown_handle) = https_ingester(addr, certs, key[0].clone());

    let dir = tempdir().expect("Couldn't create temp dir...");

    let mut cmd = Command::cargo_bin("logdna-agent").unwrap();

    let dir_path = format!("{}/", dir.path().to_str().unwrap());

    let agent = cmd
        .env_clear()
        .env("RUST_LOG", "debug")
        .env("RUST_BACKTRACE", "full")
        .env("SSL_CERT_FILE", cert_file.path().to_str().unwrap())
        .env("LOGDNA_LOG_DIRS", &dir_path)
        .env("LOGDNA_HOST", "localhost:1338")
        .env("LOGDNA_LOOKBACK", "none")
        .env("LOGDNA_INGESTION_KEY", "1234")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let log_lines = "This is a test log line";

    let file_path = dir.path().join("test.log");
    let mut file = File::create(&file_path).expect("Couldn't create temp log file...");

    // Enough bytes to get past the lookback threshold
    let line_write_count = (8192 / (log_lines.as_bytes().len() + 1)) + 1;
    (0..line_write_count)
        .for_each(|_| writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file..."));
    file.sync_all().expect("Failed to sync file");

    let mut handle = agent.spawn().expect("Failed to start agent");
    // Dump the agent's stdout
    // TODO: assert that it's successfully uploaded

    thread::sleep(std::time::Duration::from_secs(1));
    tokio_test::block_on(async {
        let (line_count, _, server) = tokio::join!(
            async {
                tokio::time::delay_for(tokio::time::Duration::from_millis(5000)).await;
                let line_count = received
                    .lock()
                    .await
                    .get(file_path.to_str().unwrap())
                    .unwrap()
                    .0
                    .load(std::sync::atomic::Ordering::Relaxed);
                shutdown_handle();
                let mut output = String::new();

                handle.kill().unwrap();
                let stderr_ref = handle.stderr.as_mut().unwrap();

                stderr_ref.read_to_string(&mut output).unwrap();
                handle.wait().unwrap();
                line_count
            },
            async move {
                tokio::time::delay_for(tokio::time::Duration::from_millis(500)).await;
                (0..5).for_each(|_| {
                    writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
                    file.sync_all().expect("Failed to sync file");
                });
                tokio::time::delay_for(tokio::time::Duration::from_millis(500)).await;
                // Hack to drive stream forward
                writeln!(file, "{}", log_lines).expect("Couldn't write to temp log file...");
                file.sync_all().expect("Failed to sync file");
            },
            server
        );
        server.unwrap();
        assert_eq!(line_count, 5);
    });
}
