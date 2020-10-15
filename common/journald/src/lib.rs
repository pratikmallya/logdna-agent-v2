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
            mpsc::{sync_channel, Sender, Receiver},
            Arc,
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

    struct SharedState {
        waker: Option<Waker>,
    }

    pub struct JournaldStream {
        thread: Option<JoinHandle<()>>,
        receiver: Receiver<String>,
        shared_state: Arc<Mutex<SharedState>>,
    }

    impl JournaldStream {
        pub fn new() -> io::Result<Self> {
            let (sender, receiver) = sync_channel(100);

            let shared_state = Arc::new(Mutex::new(SharedState {
                waker: None,
            }));

            let thread_shared_state = shared_state.clone();
            let thread = Some(thread::spawn(move || {
                println!("Start journald stream side thread");
                let mut journal = JournaldSource::new();

                loop {
                    if let RecordStatus::Line(line) = journal.process_next_record() {
                        println!("Journald side thread pulled out some data");
                        sender.send(line).expect("Unable to communicate from journald stream thread worker to main stream");
                        if let Some(waker) = thread_shared_state.lock().unwrap().waker.take() {
                            waker.wake()
                        }
                    } else {
                        println!("Journald side thread found nothing - waiting for more data");
                        journal.reader.wait(None);
                    }
                }
            }));

            Ok(Self {
                thread,
                receiver,
                shared_state,
            })
        }
    }

    impl Stream for JournaldStream {
        type Item = String;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let self_ = self.as_mut();
            let mut shared_state = self_.shared_state.lock().unwrap();

            println!("Polling journald for some data");
            if let Ok(line) = self_.receiver.try_recv() {
                return Poll::Ready(Some(line));
            }

            println!("Nothing found, waiting for more data");
            shared_state.waker = Some(cx.waker().clone());

            Poll::Pending
        }
    }

    impl Drop for JournaldStream {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                thread.join();
            }
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
