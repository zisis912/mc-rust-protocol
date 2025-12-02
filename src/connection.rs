use aes::cipher::{BlockDecryptMut, BlockEncryptMut, BlockSizeUser, generic_array::GenericArray};
use std::io::{self, Read, Write};

pub type Aes128Cfb8Enc = cfb8::Encryptor<aes::Aes128>;
pub type Aes128Cfb8Dec = cfb8::Decryptor<aes::Aes128>;

pub struct StreamDecryptor<R: Read> {
    cipher: Aes128Cfb8Dec,
    reader: R,
}

impl<R: Read> StreamDecryptor<R> {
    pub fn new(cipher: Aes128Cfb8Dec, reader: R) -> Self {
        Self { cipher, reader }
    }
}

impl<R: Read> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let reader = &mut self.reader;
        let cipher = &mut self.cipher;

        let bytes_read = reader.read(buf)?;

        for block in buf[..bytes_read].chunks_mut(Aes128Cfb8Dec::block_size()) {
            cipher.decrypt_block_mut(block.into());
        }

        Ok(bytes_read)
    }
}

///NOTE: This makes lots of small writes; make sure there is a buffer somewhere down the line
/// or atleast this is the documentation that came along with the skidded code before i converted it
/// to synchronous writes
pub struct StreamEncryptor<W: Write> {
    cipher: Aes128Cfb8Enc,
    writer: W,
    // last_unwritten_encrypted_byte: Option<u8>,
}

impl<W: Write> StreamEncryptor<W> {
    pub fn new(cipher: Aes128Cfb8Enc, writer: W) -> Self {
        Self { cipher, writer }
    }
}

impl<W: Write> Write for StreamEncryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let cipher = &mut self.cipher;
        let writer = &mut self.writer;

        let mut total_written = 0;

        for block in buf.chunks(Aes128Cfb8Enc::block_size()) {
            let mut out = [0u8];

            let out_block = GenericArray::from_mut_slice(&mut out);
            cipher.encrypt_block_b2b_mut(block.into(), out_block);

            let bytes_written = writer.write(&out)?;
            total_written += bytes_written
        }

        Ok(total_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = &mut self.writer;
        writer.flush()
    }
}
