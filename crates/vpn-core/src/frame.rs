//! Message framing and the wire format of protocol v1.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{Cipher, CryptoError};
use crate::target::{Host, Target};

/// Maximum ciphertext frame length accepted on the wire.
pub const MAX_FRAME: usize = 64 * 1024;
/// Maximum payload bytes carried in a single `Data` message.
pub const MAX_DATA: usize = 32 * 1024;

const K_CONNECT: u8 = 0x01;
const K_CONNECT_OK: u8 = 0x02;
const K_CONNECT_ERR: u8 = 0x03;
const K_DATA: u8 = 0x04;
const K_CLOSE: u8 = 0x05;

const A_IPV4: u8 = 0x01;
const A_DOMAIN: u8 = 0x03;
const A_IPV6: u8 = 0x04;

/// Errors that can occur while reading or writing frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("connection closed in the middle of a frame")]
    Eof,
    #[error("frame is too large: {0} bytes")]
    FrameTooBig(usize),
    #[error("message is truncated")]
    Truncated,
    #[error("unknown message kind 0x{0:02x}")]
    UnknownKind(u8),
    #[error("unknown address type 0x{0:02x}")]
    UnknownAtyp(u8),
    #[error("message is not allowed at this point")]
    Unexpected,
}

/// A message exchanged inside the encrypted tunnel.
#[derive(Debug)]
pub enum Message {
    Connect(Target),
    ConnectOk,
    ConnectError(String),
    Data(Bytes),
    Close,
}

impl Message {
    fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(64);
        match self {
            Message::Connect(target) => {
                buf.put_u8(K_CONNECT);
                match &target.host {
                    Host::Ip(IpAddr::V4(v4)) => {
                        buf.put_u8(A_IPV4);
                        buf.extend_from_slice(&v4.octets());
                    }
                    Host::Ip(IpAddr::V6(v6)) => {
                        buf.put_u8(A_IPV6);
                        buf.extend_from_slice(&v6.octets());
                    }
                    Host::Domain(domain) => {
                        buf.put_u8(A_DOMAIN);
                        let bytes = domain.as_bytes();
                        let len = bytes.len().min(u8::MAX as usize);
                        buf.put_u8(len as u8);
                        buf.extend_from_slice(&bytes[..len]);
                    }
                }
                buf.put_u16(target.port);
            }
            Message::ConnectOk => {
                buf.put_u8(K_CONNECT_OK);
            }
            Message::ConnectError(err) => {
                buf.put_u8(K_CONNECT_ERR);
                let bytes = err.as_bytes();
                let len = bytes.len().min(u16::MAX as usize);
                buf.put_u16(len as u16);
                buf.extend_from_slice(&bytes[..len]);
            }
            Message::Data(data) => {
                buf.put_u8(K_DATA);
                buf.extend_from_slice(data);
            }
            Message::Close => {
                buf.put_u8(K_CLOSE);
            }
        }
        buf
    }

    fn decode(plain: &[u8]) -> Result<Message, FrameError> {
        let mut buf = Bytes::copy_from_slice(plain);
        match take_u8(&mut buf)? {
            K_CONNECT => {
                let host = match take_u8(&mut buf)? {
                    A_IPV4 => {
                        let octets: [u8; 4] =
                            take_bytes(&mut buf, 4)?.as_ref().try_into().unwrap();
                        Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
                    }
                    A_IPV6 => {
                        let octets: [u8; 16] =
                            take_bytes(&mut buf, 16)?.as_ref().try_into().unwrap();
                        Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
                    }
                    A_DOMAIN => {
                        let len = take_u8(&mut buf)? as usize;
                        let bytes = take_bytes(&mut buf, len)?;
                        Host::Domain(String::from_utf8_lossy(&bytes).into_owned())
                    }
                    atyp => return Err(FrameError::UnknownAtyp(atyp)),
                };
                let port = take_u16(&mut buf)?;
                Ok(Message::Connect(Target { host, port }))
            }
            K_CONNECT_OK => Ok(Message::ConnectOk),
            K_CONNECT_ERR => {
                let len = take_u16(&mut buf)? as usize;
                let bytes = take_bytes(&mut buf, len)?;
                Ok(Message::ConnectError(
                    String::from_utf8_lossy(&bytes).into_owned(),
                ))
            }
            K_DATA => Ok(Message::Data(buf)),
            K_CLOSE => Ok(Message::Close),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

fn take_u8(buf: &mut Bytes) -> Result<u8, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::Truncated);
    }
    Ok(buf.get_u8())
}

fn take_u16(buf: &mut Bytes) -> Result<u16, FrameError> {
    if buf.remaining() < 2 {
        return Err(FrameError::Truncated);
    }
    Ok(buf.get_u16())
}

fn take_bytes(buf: &mut Bytes, len: usize) -> Result<Bytes, FrameError> {
    if buf.remaining() < len {
        return Err(FrameError::Truncated);
    }
    Ok(buf.split_to(len))
}

/// Reads and decrypts frames from an underlying reader.
pub struct FrameReader<R> {
    io: R,
    cipher: Cipher,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(io: R, cipher: Cipher) -> Self {
        Self {
            io,
            cipher,
            buf: BytesMut::with_capacity(8 * 1024),
        }
    }

    /// Returns the next message, or `None` on a clean EOF.
    pub async fn recv(&mut self) -> Result<Option<Message>, FrameError> {
        loop {
            if self.buf.len() >= 4 {
                let len =
                    u32::from_le_bytes(self.buf[..4].try_into().expect("length was checked")) as usize;
                if len > MAX_FRAME {
                    return Err(FrameError::FrameTooBig(len));
                }
                if self.buf.len() >= 4 + len {
                    self.buf.advance(4);
                    let sealed = self.buf.split_to(len);
                    let plain = self.cipher.open(&sealed)?;
                    return Ok(Some(Message::decode(&plain)?));
                }
            }
            let n = self.io.read_buf(&mut self.buf).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::Eof)
                };
            }
        }
    }
}

/// Encrypts and writes frames to an underlying writer.
pub struct FrameWriter<W> {
    io: W,
    cipher: Cipher,
    buf: BytesMut,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(io: W, cipher: Cipher) -> Self {
        Self {
            io,
            cipher,
            buf: BytesMut::with_capacity(MAX_DATA + 64),
        }
    }

    /// Sends a message, splitting oversized `Data` into several frames.
    pub async fn send(&mut self, message: &Message) -> Result<(), FrameError> {
        match message {
            Message::Data(data) => {
                for chunk in data.chunks(MAX_DATA) {
                    self.send_one(&Message::Data(Bytes::copy_from_slice(chunk)))
                        .await?;
                }
                Ok(())
            }
            other => self.send_one(other).await,
        }
    }

    async fn send_one(&mut self, message: &Message) -> Result<(), FrameError> {
        let plain = message.encode();
        let sealed = self.cipher.seal(&plain);
        if sealed.len() > MAX_FRAME {
            return Err(FrameError::FrameTooBig(sealed.len()));
        }
        self.buf.clear();
        self.buf.put_u32_le(sealed.len() as u32);
        self.buf.extend_from_slice(&sealed);
        self.io.write_all(&self.buf).await?;
        self.io.flush().await?;
        Ok(())
    }
}

/// A duplex framed connection over a reader/writer pair.
pub struct Framed<R, W> {
    reader: FrameReader<R>,
    writer: FrameWriter<W>,
}

impl<R, W> Framed<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W, cipher: Cipher) -> Self {
        Self {
            reader: FrameReader::new(reader, cipher.clone()),
            writer: FrameWriter::new(writer, cipher),
        }
    }

    pub async fn recv(&mut self) -> Result<Option<Message>, FrameError> {
        self.reader.recv().await
    }

    pub async fn send(&mut self, message: &Message) -> Result<(), FrameError> {
        self.writer.send(message).await
    }

    pub fn into_split(self) -> (FrameReader<R>, FrameWriter<W>) {
        (self.reader, self.writer)
    }
}
