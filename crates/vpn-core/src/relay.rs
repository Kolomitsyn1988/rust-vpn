//! Bidirectional relay between encrypted frames and a raw TCP stream.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::{FrameError, FrameReader, FrameWriter, Framed, Message};

const RELAY_BUFFER_SIZE: usize = 16 * 1024;

/// Pumps raw bytes into encrypted `Data` frames.
pub async fn pump_raw_to_frames<R, W>(
    mut reader: R,
    mut writer: FrameWriter<W>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; RELAY_BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            writer.send(&Message::Close).await?;
            return Ok(());
        }
        writer
            .send(&Message::Data(Bytes::copy_from_slice(&buffer[..n])))
            .await?;
    }
}

/// Pumps decrypted frames into a raw writer.
pub async fn pump_frames_to_raw<R, W>(
    mut reader: FrameReader<R>,
    mut writer: W,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Some(message) = reader.recv().await? {
        match message {
            Message::Data(data) => {
                writer.write_all(&data).await?;
            }
            Message::Close => {
                let _ = writer.shutdown().await;
                return Ok(());
            }
            _ => return Err(FrameError::Unexpected),
        }
    }
    Ok(())
}

/// Relays bytes in both directions until either side finishes.
pub async fn relay<R1, W1, R2, W2>(
    framed: Framed<R1, W1>,
    raw_reader: R2,
    raw_writer: W2,
) -> Result<(), FrameError>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let (frame_reader, frame_writer) = framed.into_split();
    tokio::select! {
        result = pump_raw_to_frames(raw_reader, frame_writer) => result,
        result = pump_frames_to_raw(frame_reader, raw_writer) => result,
    }
}
