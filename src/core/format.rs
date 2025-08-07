use crate::core::error::AegisError;
// Only import `Read` when the `verifier` feature is enabled.
#[cfg(feature = "verifier")]
use std::io::Read;
use std::io::Write;

const MAGIC_NUMBER: &[u8; 6] = b"AEGIS1";

#[cfg(feature = "verifier")]
const MAX_BLOCK_SIZE: u64 = 1_000_000_000; // 1GB limit

pub struct AegisAncient {
    pub public_key: Vec<u8>,
    pub metadata: String,
    pub signature: Vec<u8>,
    pub image_data: Vec<u8>,
}

impl AegisAncient {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), AegisError> {
        writer.write_all(MAGIC_NUMBER)?;
        let write_block = |data: &[u8], w: &mut W| -> std::io::Result<()> {
            w.write_all(&(data.len() as u64).to_be_bytes())?;
            w.write_all(data)
        };
        write_block(&self.public_key, writer)?;
        write_block(self.metadata.as_bytes(), writer)?;
        write_block(&self.signature, writer)?;
        write_block(&self.image_data, writer)?;
        Ok(())
    }

    #[cfg(feature = "verifier")]
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, AegisError> {
        let mut magic_buf = [0u8; 6];
        reader.read_exact(&mut magic_buf)?;
        if magic_buf != *MAGIC_NUMBER {
            return Err(AegisError::InvalidFormat);
        }
        let read_block = |r: &mut R| -> Result<Vec<u8>, AegisError> {
            let mut len_buf = [0u8; 8];
            r.read_exact(&mut len_buf)?;
            let len = u64::from_be_bytes(len_buf);
            if len > MAX_BLOCK_SIZE {
                return Err(AegisError::InvalidFormat);
            }
            let mut data_buf = Vec::with_capacity(len as usize);
            let mut limited_reader = r.take(len);
            limited_reader.read_to_end(&mut data_buf)?;
            if data_buf.len() as u64 != len {
                return Err(AegisError::InvalidFormat);
            }
            Ok(data_buf)
        };
        let public_key = read_block(reader)?;
        let metadata_bytes = read_block(reader)?;
        let metadata = String::from_utf8(metadata_bytes).map_err(|_| AegisError::InvalidFormat)?;
        let signature = read_block(reader)?;
        let image_data = read_block(reader)?;
        Ok(AegisAncient {
            public_key,
            metadata,
            signature,
            image_data,
        })
    }
}