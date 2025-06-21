use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Seek, Write};
use std::path::Path;

pub use super::iter::BincodeIterator;

const BUFFER_SIZE: usize = 1000;

pub trait DiskBuffer<T>
where
    Self: Sized,
{
    /// Returns a mutable reference to the internal buffer
    fn buffer_mut(&mut self) -> &mut Vec<T>;
    /// Flush the buffer to disk
    fn flush_buffer(&mut self) -> Result<(), Box<dyn Error>>;
    /// Add an item to the buffer,
    /// Default implemetation flushes to disk if it reaches capacity
    fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.buffer_mut().push(item);

        if self.buffer_mut().len() >= self.buffer_mut().capacity() {
            self.flush_buffer()?;
        }
        Ok(())
    }

    /// Flush the buffer to disk and consume `self`
    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        self.flush_buffer()
    }
}

/// JSON lines object buffer
pub struct JsonLObjectBuffer<T>(pub ObjectBuffer<T>);
impl<T> JsonLObjectBuffer<T> {
    pub fn new(file_path: &str) -> Result<Self, Box<dyn Error>> {
        Ok(JsonLObjectBuffer(ObjectBuffer::new(file_path)?))
    }

    pub fn new_with_capacity(file_path: &str, capacity: usize) -> Result<Self, Box<dyn Error>> {
        Ok(JsonLObjectBuffer(ObjectBuffer::new_with_capacity(
            file_path, capacity,
        )?))
    }
}

pub struct BincodeObjectBuffer<T> {
    pub obj_buffer: ObjectBuffer<T>,
    pub encode_buffer: Vec<u8>,
}

impl<T> BincodeObjectBuffer<T> {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        Ok(BincodeObjectBuffer {
            obj_buffer: ObjectBuffer::new(file_path)?,
            encode_buffer: Vec::new(),
        })
    }

    pub fn new_with_capacity(
        file_path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(BincodeObjectBuffer {
            obj_buffer: ObjectBuffer::new_with_capacity(file_path, capacity)?,
            encode_buffer: Vec::new(),
        })
    }
}

impl<T: bincode::Decode<()>> BincodeObjectBuffer<T> {
    pub fn into_reader(
        self,
    ) -> Result<BincodeIterator<T, BufReader<std::fs::File>>, Box<dyn Error>> {
        let mut inner = self.obj_buffer.writer.into_inner()?;
        inner.seek(std::io::SeekFrom::Start(0))?;
        Ok(BincodeIterator::from_file(inner))
    }
}

impl<T> DiskBuffer<T> for JsonLObjectBuffer<T>
where
    T: serde::Serialize,
{
    #[inline]
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        &mut self.0.buffer
    }

    fn flush_buffer(&mut self) -> Result<(), Box<dyn Error>> {
        for item in self.0.buffer.drain(..) {
            let json_line = serde_json::to_string(&item)?;
            writeln!(self.0.writer, "{json_line}")?;
        }
        self.0.writer.flush()?;
        Ok(())
    }
}

impl<T> DiskBuffer<T> for BincodeObjectBuffer<T>
where
    T: bincode::Encode,
{
    #[inline]
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        &mut self.obj_buffer.buffer
    }

    fn flush_buffer(&mut self) -> Result<(), Box<dyn Error>> {
        for item in self.obj_buffer.buffer.drain(..) {
            self.encode_buffer.clear();
            bincode::encode_into_std_write(
                &item,
                &mut self.encode_buffer,
                bincode::config::standard(),
            )?;

            let len = self.encode_buffer.len() as u32;
            self.obj_buffer.writer.write_all(&len.to_le_bytes())?;
            self.obj_buffer.writer.write_all(&self.encode_buffer)?;
        }

        self.obj_buffer.writer.flush()?;

        Ok(())
    }
}

pub struct ObjectBuffer<T> {
    buffer: Vec<T>,
    writer: BufWriter<std::fs::File>,
}

impl<T> ObjectBuffer<T> {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true) // read so we can read back the file later
            .truncate(true)
            .open(file_path)?;

        Ok(ObjectBuffer {
            buffer: Vec::with_capacity(BUFFER_SIZE),
            writer: BufWriter::new(file),
        })
    }

    pub fn new_with_capacity(
        file_path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true) // read so we can read back the file later
            .truncate(true)
            .open(file_path)?;

        Ok(ObjectBuffer {
            buffer: Vec::with_capacity(capacity),
            writer: BufWriter::new(file),
        })
    }
}

/// Loads a `Vec<T>` from a JSON Lines file
pub fn jsonl_load<T>(file_path: impl AsRef<Path>) -> Result<Vec<T>, Box<dyn Error>>
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

pub fn bincode_load<T>(file_path: impl AsRef<Path>) -> Result<Vec<T>, Box<dyn Error>>
where
    T: bincode::Decode<()>,
{
    use std::io::Read;

    let file = std::fs::File::open(file_path.as_ref())?;
    let mut buf_reader = BufReader::new(file);
    let mut items = Vec::new();

    loop {
        let mut len_bytes = [0u8; 4];
        match buf_reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_le_bytes(len_bytes) as usize;

        let mut data = vec![0u8; len];
        buf_reader.read_exact(&mut data)?;

        let (item, _) = bincode::decode_from_slice::<T, _>(&data, bincode::config::standard())?;
        items.push(item);
    }

    Ok(items)
}
