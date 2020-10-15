pub mod source {
    #[macro_use]
    use systemd::journal::{Journal, JournalFiles, JournalRecord, JournalSeek};
    use chrono::{Local, TimeZone};

    use log::{warn};

    use futures::stream::Stream;
    use std::{
        io,
        path::Path,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
        task::{Context, Poll, Waker},
        thread::{self, JoinHandle},
        time::UNIX_EPOCH,
    };

    const KEY_TRANSPORT: &str = "_TRANSPORT";
    const KEY_HOSTNAME: &str = "_HOSTNAME";
    const KEY_COMM: &str = "_COMM";
    const KEY_PID: &str = "_PID";
    const KEY_MESSAGE: &str = "MESSAGE";

    const TRANSPORT_AUDIT: &str = "audit";
    const TRANSPORT_DRIVER: &str = "driver";
    const TRANSPORT_SYSLOG: &str = "syslog";
    const TRANSPORT_JOURNAL: &str = "journal";
    const TRANSPORT_STDOUT: &str = "stdout";
    const TRANSPORT_KERNEL: &str = "kernel";

    pub enum RecordStatus {
        Line(String),
        BadLine,
        NoLines,
    }

    pub struct SharedState {
        line: Option<String>,
        waker: Option<Waker>,
    }

    pub struct JournaldStream {
        thread: JoinHandle<()>,
        shared_state: Arc<Mutex<SharedState>>,
        flag: Arc<AtomicBool>
    }

    impl JournaldStream {
        pub fn new() -> io::Result<Self> {
            let shared_state = Arc::new(Mutex::new(SharedState {
                line: None,
                waker: None,
            }));

            let flag = Arc::new(AtomicBool::new(false));
            let thread_flag = Arc::clone(&flag);
            let thread_shared_state = shared_state.clone();
            let thread = thread::spawn(move || {
                println!("Start journald stream side thread");
                let mut journal = JournaldSource::new();

                loop {
                    while !thread_flag.load(Ordering::Acquire) {
                        println!("Parking journald side thread");
                        thread::park();
                    }
                    println!("Releasing journald side thread");

                    loop {
                        if let RecordStatus::Line(line) = journal.process_next_record() {
                            println!("Journald side thread pulled out some data");
                            let mut shared_state = thread_shared_state.lock().unwrap();
                            shared_state.line = Some(line);
                            thread_flag.store(false, Ordering::Release);
                            if let Some(waker) = shared_state.waker.take() {
                                waker.wake()
                            }
                            break;
                        } else {
                            println!("Journald side thread found nothing - waiting for more data");
                            journal.reader.wait(None);
                        }
                    }
                }
            });

            Ok(Self {
                thread,
                shared_state,
                flag,
            })
        }
    }

    impl Stream for JournaldStream {
        type Item = String;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let self_ = self.as_mut();
            let mut shared_state = self_.shared_state.lock().unwrap();

            println!("Polling journald for some data");
            if let Some(line) = shared_state.line.take() {
                return Poll::Ready(Some(line));
            }

            println!("Nothing found, waiting for more data");
            shared_state.waker = Some(cx.waker().clone());
            self_.flag.store(true, Ordering::Release);
            self_.thread.thread().unpark();

            Poll::Pending
        }
    }

    pub struct JournaldSource {
        reader: Journal,
    }

    impl JournaldSource {
        pub fn new() -> JournaldSource {
            let mut reader = Journal::open_directory(&Path::new("/var/log/journal"), JournalFiles::All, false)
                .expect("Could not open journald reader");
            reader
                .seek(JournalSeek::Tail)
                .expect("Could not seek to tail of journald logs");

            JournaldSource { reader }
        }

        pub fn process_next_record(&mut self) -> RecordStatus {
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

            match record.get(KEY_TRANSPORT) {
                Some(transport) => match transport.as_ref() {
                    TRANSPORT_AUDIT => self.process_audit_record(&record, timestamp),
                    TRANSPORT_DRIVER | TRANSPORT_SYSLOG | TRANSPORT_JOURNAL | TRANSPORT_STDOUT => {
                        self.process_default_record(&record, transport, timestamp)
                    }
                    TRANSPORT_KERNEL => self.process_kernel_record(&record, timestamp),
                    _ => {
                        warn!(
                            "Got unexpected transport for journald record: {}",
                            transport
                        );
                        RecordStatus::BadLine
                    }
                },
                None => {
                    warn!("Unable to get transport of journald record");
                    RecordStatus::BadLine
                }
            }
        }

        fn process_audit_record(&self, record: &JournalRecord, timestamp: String) -> RecordStatus {
            let hostname = match record.get(KEY_HOSTNAME) {
                Some(hostname) => hostname,
                None => {
                    warn!("Unable to get hostname of journald audit record");
                    return RecordStatus::BadLine;
                }
            };

            let pid = match record.get(KEY_PID) {
                Some(pid) => pid,
                None => {
                    warn!("Unable to get pid of journald audit record");
                    return RecordStatus::BadLine;
                }
            };

            let message = match record.get(KEY_MESSAGE) {
                Some(message) => message,
                None => {
                    warn!("Unable to get message of journald audit record");
                    return RecordStatus::BadLine;
                }
            };

            RecordStatus::Line(format!(
                "{} {} audit[{}]: {}",
                timestamp, hostname, pid, message
            ))
        }

        fn process_default_record(
            &self,
            record: &JournalRecord,
            record_type: &String,
            timestamp: String,
        ) -> RecordStatus {
            let hostname = match record.get(KEY_HOSTNAME) {
                Some(hostname) => hostname,
                None => {
                    warn!("Unable to get hostname of journald {} record", record_type);
                    return RecordStatus::BadLine;
                }
            };

            let comm = match record.get(KEY_COMM) {
                Some(comm) => comm,
                None => {
                    warn!("Unable to get comm of journald {} record", record_type);
                    return RecordStatus::BadLine;
                }
            };

            let pid = match record.get(KEY_PID) {
                Some(pid) => pid,
                None => {
                    warn!("Unable to get pid of journald {} record", record_type);
                    return RecordStatus::BadLine;
                }
            };

            let message = match record.get(KEY_MESSAGE) {
                Some(message) => message,
                None => {
                    warn!("Unable to get message of journald {} record", record_type);
                    return RecordStatus::BadLine;
                }
            };

            RecordStatus::Line(format!(
                "{} {} {}[{}]: {}",
                timestamp, hostname, comm, pid, message
            ))
        }

        fn process_kernel_record(&self, record: &JournalRecord, timestamp: String) -> RecordStatus {
            let hostname = match record.get(KEY_HOSTNAME) {
                Some(hostname) => hostname,
                None => {
                    warn!("Unable to get hostname of journald kernel record");
                    return RecordStatus::BadLine;
                }
            };

            let message = match record.get(KEY_MESSAGE) {
                Some(message) => message,
                None => {
                    warn!("Unable to get message of journald kernel record");
                    return RecordStatus::BadLine;
                }
            };

            RecordStatus::Line(format!("{} {} kernel: {}", timestamp, hostname, message))
        }
    }
}

mod tests {
    use super::source::JournaldSource;

    use futures::stream::StreamExt;
    use tokio;

    #[tokio::test]
    async fn source_works() {
        let source = JournaldSource::new();
        let mut stream = source.into_stream().unwrap();
        while let Some(line) = stream.next().await {
            println!("{}", line);
        }
    }
}
