//! Bounded CPU workers parse and hash independently. Results are committed in
//! submission order; newly named contextual definitions are queued immediately,
//! including jobs dispatched before their names became available.
use super::*;
use std::{
    sync::{Mutex, mpsc},
    thread,
    time::Duration,
};

struct Job {
    sequence: usize,
    source: usize,
    index: usize,
    name: String,
}

impl NameRecovery {
    /// Runs recovery to a fixed point using the available CPU parallelism.
    /// `report` runs on the calling thread, including while readers are busy;
    /// its final argument is true after all contextual rereads have completed.
    /// Per-entry failures are retained by `take_errors`; cancellation stops and
    /// joins all workers before returning `Error::Cancelled`.
    pub fn run(&mut self, cancel: &AtomicBool, report: impl FnMut(&mut Self, bool)) -> Result<()> {
        let workers = thread::available_parallelism().map_or(1, usize::from);
        self.run_workers(workers, cancel, report)
    }

    fn run_workers(
        &mut self,
        workers: usize,
        cancel: &AtomicBool,
        mut report: impl FnMut(&mut Self, bool),
    ) -> Result<()> {
        check(cancel)?;
        let workers = workers.min(self.pending.len());
        if workers == 0 {
            report(self, true);
            return Ok(());
        }
        let sources = self.sources.clone();
        // Workers need immutable target hashes, never partially updated names.
        let directories: BTreeSet<_> = self.directories.keys().cloned().collect();
        let files: BTreeSet<_> = self.files.keys().cloned().collect();
        let (jobs_tx, jobs_rx) = mpsc::channel::<Job>();
        let jobs_rx = Mutex::new(jobs_rx);
        let (results_tx, results_rx) = mpsc::channel();
        thread::scope(|scope| {
            let mut handles = Vec::new();
            let result = (|| {
                for worker in 0..workers {
                    let (sources, directories, files, jobs_rx) =
                        (&sources, &directories, &files, &jobs_rx);
                    let results_tx = results_tx.clone();
                    handles.push(
                        thread::Builder::new()
                            .name(format!("hxv4-names-{worker}"))
                            .spawn_scoped(scope, move || {
                                loop {
                                    let job = match jobs_rx.lock() {
                                        Ok(receiver) => receiver.recv(),
                                        Err(_) => break,
                                    };
                                    let Ok(job) = job else { break };
                                    let result = sources[job.source].find(
                                        job.index,
                                        &job.name,
                                        cancel,
                                        |directory, hash| {
                                            if directory {
                                                directories.contains(hash)
                                            } else {
                                                files.contains(hash)
                                            }
                                        },
                                    );
                                    let stopped = matches!(result, Err(Error::Cancelled));
                                    if results_tx.send((job, result)).is_err() || stopped {
                                        break;
                                    }
                                }
                            })?,
                    );
                }
                drop(results_tx);
                let mut dispatched = 0;
                let mut committed = 0;
                let mut ready = BTreeMap::new();
                loop {
                    check(cancel)?;
                    // Count completed-but-uncommitted jobs as outstanding so a
                    // slow earlier resource cannot accumulate unbounded results.
                    while dispatched - committed < workers {
                        let Some((source, index)) = self.pending.pop_front() else {
                            break;
                        };
                        let name = self.resolve(&self.sources[source].archive.entries[index].name);
                        jobs_tx
                            .send(Job {
                                sequence: dispatched,
                                source,
                                index,
                                name,
                            })
                            .map_err(|_| std::io::Error::other("Hxv4 name workers disconnected"))?;
                        dispatched += 1;
                    }
                    if dispatched == committed {
                        self.requeue(cancel)?;
                        if self.pending.is_empty() {
                            report(self, true);
                            return check(cancel);
                        }
                        continue;
                    }
                    match results_rx.recv_timeout(Duration::from_millis(50)) {
                        Ok((job, result)) => {
                            ready.insert(job.sequence, (job, result));
                            while let Some((job, result)) = ready.remove(&committed) {
                                check(cancel)?;
                                self.complete(job.source, job.index, &job.name, result)?;
                                committed += 1;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(
                                std::io::Error::other("Hxv4 name workers disconnected").into()
                            );
                        }
                    }
                    report(self, false);
                }
            })();
            // Dropping both endpoints releases waiting workers on every exit,
            // including cancellation, channel failure and partial spawn failure.
            drop(jobs_tx);
            drop(results_rx);
            let mut panicked = false;
            for handle in handles {
                panicked |= handle.join().is_err();
            }
            result?;
            if panicked {
                return Err(std::io::Error::other("Hxv4 name worker panicked").into());
            }
            Ok(())
        })
    }
}
