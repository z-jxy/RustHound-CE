use std::collections::VecDeque;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};

const BUFFER_SIZE: usize = 1000;

pub struct ObjectBuffer<T> {
    buffer: VecDeque<T>,
    writer: BufWriter<std::fs::File>,
}

impl<T: serde::Serialize> ObjectBuffer<T> {
    pub fn new(file_path: &str) -> Result<Self, Box<dyn Error>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)?;

        Ok(ObjectBuffer {
            buffer: VecDeque::with_capacity(BUFFER_SIZE),
            writer: BufWriter::new(file),
        })
    }

    pub fn new_with_capacity(file_path: &str, capacity: usize) -> Result<Self, Box<dyn Error>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)?;

        Ok(ObjectBuffer {
            buffer: VecDeque::with_capacity(capacity),
            writer: BufWriter::new(file),
        })
    }

    pub fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.buffer.push_back(item);

        if self.buffer.len() >= self.buffer.capacity() {
            self.flush_buffer()?;
        }
        Ok(())
    }

    pub fn flush_buffer(&mut self) -> Result<(), Box<dyn Error>> {
        while let Some(item) = self.buffer.pop_front() {
            let json_line = serde_json::to_string(&item)?;
            writeln!(self.writer, "{json_line}")?;
        }
        self.writer.flush()?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), Box<dyn Error>> {
        self.flush_buffer()?;
        Ok(())
    }
}

/// Loads a `Vec<T>` from a JSON Lines file
pub fn jsonl_load<T>(file_path: impl AsRef<std::path::Path>) -> Result<Vec<T>, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    let file = std::fs::File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            out.push(serde_json::from_str(&line)?);
        }
    }

    Ok(out)
}
