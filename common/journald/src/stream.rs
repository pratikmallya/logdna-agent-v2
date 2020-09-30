use chrono::{Local, TimeZone};
use futures::stream::Stream as FutureStream;
use http::types::body::LineBuilder;
use log::warn;
use metrics::Metrics;
use std::{
    mem::drop,
    path::PathBuf,
    pin::Pin,
    sync::{
        mpsc::{sync_channel, Receiver, TryRecvError},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle},
    time::{Duration, UNIX_EPOCH},
};
use systemd::journal::{Journal, JournalFiles, JournalRecord, JournalSeek};

const KEY_MESSAGE: &str = "MESSAGE";
const KEY_SYSTEMD_UNIT: &str = "_SYSTEMD_UNIT";
const KEY_SYSLOG_IDENTIFIER: &str = "SYSLOG_IDENTIFIER";
const KEY_CONTAINER_NAME: &str = "CONTAINER_NAME";
const DEFAULT_APP: &str = "UNKNOWN_SYSTEMD_APP";

#[derive(Clone)]
pub enum Path {
    Directory(PathBuf),
    Files(Vec<PathBuf>),
}

enum RecordStatus {
    Line(LineBuilder),
    BadLine,
    NoLines,
}

struct SharedState {
    waker: Option<Waker>,
    is_alive: bool,
}

pub struct Stream {
    thread: Option<JoinHandle<()>>,
    receiver: Option<Receiver<LineBuilder>>,
    shared_state: Arc<Mutex<SharedState>>,
    path: Path,
}

impl Stream {
    pub fn new(path: Path) -> Self {
        let mut stream = Self {
            thread: None,
            receiver: None,
            shared_state: Arc::new(Mutex::new(SharedState {
                waker: None,
                is_alive: true,
            })),
            path,
        };

        stream.spawn_thread();
        stream
    }

    fn spawn_thread(&mut self) {
        self.drop_thread();

        let (sender, receiver) = sync_channel(100);
        self.shared_state.lock().unwrap().is_alive = true;
        let thread_shared_state = self.shared_state.clone();
        let path = self.path.clone();
        let thread = thread::spawn(move || {
            let mut journal = Reader::new(path);

            let call_waker = || {
                let mut shared_state = match thread_shared_state.lock() {
                    Ok(shared_state) => shared_state,
                    Err(e) => {
                        // we can't wake up the stream so it will hang indefinitely; need
                        // to panic here
                        panic!(
                            "journald's worker thread unable to access shared state: {:?}",
                            e
                        );
                    }
                };
                if let Some(waker) = shared_state.waker.take() {
                    waker.wake();
                }
            };

            loop {
                let is_alive = match thread_shared_state.lock() {
                    Ok(shared_state) => shared_state.is_alive,
                    Err(e) => {
                        // we can't wake up the stream so it will hang indefinitely; need
                        // to panic here
                        panic!(
                            "journald's worker thread unable to access shared state: {:?}",
                            e
                        );
                    }
                };

                if !is_alive {
                    break;
                } else if let RecordStatus::Line(line) = journal.process_next_record() {
                    if let Err(e) = sender.send(line) {
                        warn!(
                            "journald's worker thread unable to communicate with main thread: {}",
                            e
                        );
                        break;
                    }

                    call_waker();
                } else if let Err(e) = journal.reader.wait(Some(Duration::from_millis(100))) {
                    warn!(
                        "journald's worker thread unable to poll journald for next record: {}",
                        e
                    );
                    break;
                }
            }

            // some sort of error has occurred. Explicitly drop the sender before waking up the
            // stream to prevent a race condition
            drop(sender);
            call_waker();
        });

        self.thread = Some(thread);
        self.receiver = Some(receiver);
    }

    fn drop_thread(&mut self) {
        self.shared_state.lock().unwrap().is_alive = false;
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                warn!("unable to join journald's worker thread: {:?}", e)
            }
        }
    }
}

impl FutureStream for Stream {
    type Item = Vec<LineBuilder>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut self_ = self.as_mut();

        if let Some(ref receiver) = self_.receiver {
            match receiver.try_recv() {
                Ok(line) => {
                    return Poll::Ready(Some(vec![line]));
                }
                Err(TryRecvError::Disconnected) => {
                    warn!("journald's main thread unable to read from worker thread, restarting worker thread...");
                    self_.drop_thread();
                    self_.spawn_thread();
                }
                _ => {}
            }
        } else {
            warn!(
                "journald's main thread missing connection to worker thread, shutting down stream"
            );
            return Poll::Ready(None);
        }

        let mut shared_state = self_.shared_state.lock().unwrap();
        shared_state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.drop_thread();
    }
}

struct Reader {
    reader: Journal,
}

impl Reader {
    fn new(path: Path) -> Self {
        let mut reader = match path {
            Path::Directory(path) => Journal::open_directory(&path, JournalFiles::All, false)
                .expect("Could not open journald reader for directory"),
            Path::Files(paths) => {
                let paths: Vec<&std::path::Path> = paths.iter().map(PathBuf::as_path).collect();
                Journal::open_files(&paths).expect("Could not open journald reader for paths")
            }
        };
        reader
            .seek(JournalSeek::Tail)
            .expect("Could not seek to tail of journald logs");

        Self { reader }
    }

    fn process_next_record(&mut self) -> RecordStatus {
        let record = match self.reader.next_entry() {
            Ok(Some(record)) => record,
            Ok(None) => return RecordStatus::NoLines,
            Err(e) => panic!("Unable to read next record from journald: {}", e),
        };

        let timestamp = match self.reader.timestamp() {
            Ok(timestamp) => Local
                .timestamp(
                    timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                    0,
                )
                .format("%b %d %H:%M:%S")
                .to_string(),
            Err(e) => {
                warn!(
                    "Unable to read timestamp associated with journald record: {}",
                    e
                );
                Local::now().format("%b %d %H:%M:%S").to_string()
            }
        };

        self.process_default_record(&record, timestamp)
    }

    fn process_default_record(&self, record: &JournalRecord, _timestamp: String) -> RecordStatus {
        let message = match record.get(KEY_MESSAGE) {
            Some(message) => message,
            None => {
                warn!("unable to get message of journald record");
                return RecordStatus::BadLine;
            }
        };

        let default_app = String::from(DEFAULT_APP);
        let app = record
            .get(KEY_CONTAINER_NAME)
            .or_else(|| record.get(KEY_SYSTEMD_UNIT))
            .or_else(|| record.get(KEY_SYSLOG_IDENTIFIER))
            .or(Some(&default_app));
        let app = match app {
            Some(app) => app,
            None => {
                warn!("unable to get a suitable app name for journald record");
                return RecordStatus::BadLine;
            }
        };

        Metrics::journald().increment_lines();
        Metrics::journald().add_bytes(message.len() as u64);
        RecordStatus::Line(LineBuilder::new().line(message).file(app))
    }
}

#[cfg(all(feature = "journald_tests", test))]
mod tests {
    use super::*;
    use futures::stream::StreamExt;
    use serial_test::serial;
    use std::{thread::sleep, time::Duration};
    use systemd::journal;
    use tokio::time::timeout;

    impl RecordStatus {
        fn is_line(&self) -> bool {
            match self {
                RecordStatus::Line(_) => true,
                _ => false,
            }
        }

        fn is_no_lines(&self) -> bool {
            match self {
                RecordStatus::NoLines => true,
                _ => false,
            }
        }
    }

    const JOURNALD_LOG_PATH: &str = "/var/log/journal";

    #[tokio::test]
    #[serial]
    async fn reader_gets_new_logs() {
        journal::print(1, "Reader got the correct line!");
        sleep(Duration::from_millis(50));
        let mut reader = Reader::new(Path::Directory(JOURNALD_LOG_PATH.into()));

        let record_status = reader.process_next_record();
        assert!(record_status.is_line());

        if let RecordStatus::Line(line) = record_status {
            assert!(line.line.is_some());
            if let Some(line_str) = line.line {
                assert_eq!(line_str, "Reader got the correct line!");
            }
        }

        assert!(reader.process_next_record().is_no_lines());
    }

    #[tokio::test]
    #[serial]
    async fn stream_gets_new_logs() {
        journal::print(1, "Reader got the correct line 1!");
        sleep(Duration::from_millis(50));
        let mut stream = Stream::new(Path::Directory(JOURNALD_LOG_PATH.into()));
        sleep(Duration::from_millis(50));
        journal::print(1, "Reader got the correct line 2!");

        let first_batch = match timeout(Duration::from_millis(50), stream.next()).await {
            Err(e) => {
                panic!("unable to grab first batch of lines from stream: {:?}", e);
            }
            Ok(None) => {
                panic!("expected to get a line from journald stream");
            }
            Ok(Some(batch)) => batch,
        };

        assert_eq!(first_batch.len(), 1);
        let first_line = &first_batch[0];
        assert!(first_line.line.is_some());
        if let Some(line_str) = &first_line.line {
            assert_eq!(line_str, "Reader got the correct line 1!");
        }

        let second_batch = match timeout(Duration::from_millis(50), stream.next()).await {
            Err(e) => {
                panic!("unable to grab second batch of lines from stream: {:?}", e);
            }
            Ok(None) => {
                panic!("expected to get a line from journald stream");
            }
            Ok(Some(batch)) => batch,
        };

        assert_eq!(second_batch.len(), 1);
        let second_line = &second_batch[0];
        assert!(second_line.line.is_some());
        if let Some(line_str) = &second_line.line {
            assert_eq!(line_str, "Reader got the correct line 2!");
        }

        match timeout(Duration::from_millis(50), stream.next()).await {
            Err(_) => {}
            _ => panic!("did not expect any more events from journald stream"),
        }
    }
}
