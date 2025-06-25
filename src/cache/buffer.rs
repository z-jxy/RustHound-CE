use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::path::Path;

pub use super::iter::BincodeIterator;

const DEFAULT_BUFFER_SIZE: usize = 1000;

pub trait Storage<T>
where
    Self: Sized,
{
    /// Returns a mutable reference to the internal buffer
    fn buffer_mut(&mut self) -> &mut Vec<T>;
    
    /// Flush the buffer to disk
    fn flush(&mut self) -> Result<(), Box<dyn Error>>;

    /// Add an item to the buffer,
    /// Default implemetation flushes to disk if it reaches capacity
    fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.buffer_mut().push(item);

        if self.buffer_mut().len() >= self.buffer_mut().capacity() {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush the buffer to disk and consume `self`
    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        self.flush()
    }
}

impl <T>Storage <T> for Vec<T> {
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        self
    }

    // override since theres no need to check capacity 
    fn add(&mut self, item: T) -> Result<(), Box<dyn Error>> {
        self.push(item);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub struct BincodeObjectBuffer<T> {
    /// Main buffer for storing objects before writing to disk
    obj_buffer: ObjectBuffer<T>,
    /// Intermediate buffer for encoding objects to bincode before writing to disk
    encode_buffer: Vec<u8>,
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

impl<T> Storage<T> for BincodeObjectBuffer<T>
where
    T: bincode::Encode,
{
    #[inline]
    fn buffer_mut(&mut self) -> &mut Vec<T> {
        &mut self.obj_buffer.buffer
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
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



/// Wrapper around a `Vec<T>` and a `BufWriter` to write objects to disk.
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
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
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
