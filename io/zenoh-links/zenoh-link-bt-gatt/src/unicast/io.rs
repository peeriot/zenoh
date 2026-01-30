use std::future::Future;
use std::pin::Pin;

use bluer::gatt::remote::{
    Characteristic as RemoteCharacteristic,
    CharacteristicWriteRequest as RemoteCharacteristicWriteRequest,
};
use bluer::gatt::{CharacteristicReader, CharacteristicWriter, WriteOp};
use futures::{Stream, StreamExt};

/// A trait for reading from a GATT characteristic
///
/// Used to abstract the exact mechanism of how reading is performed, whether locally or remotely
/// and whether using BlueZ's Unix domain sockets or the traditional GATT operations on the `Characteristic` types.
pub trait GattCharRead: Send {
    /// Return the already-negotiated MTU
    fn mtu(&self) -> usize;

    /// Read up to `buf.len()` bytes into `buf`, returning the number of bytes read
    ///
    /// If the size of `buf` is less than the size of the incoming packet, a packet truncation IO error
    /// will be returned.
    ///
    /// In general, callers should provide a buffer which is always >= the negotiated MTU size.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a;
}

impl<T> GattCharRead for &mut T
where
    T: GattCharRead,
{
    fn mtu(&self) -> usize {
        T::mtu(self)
    }

    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        T::read(self, buf)
    }
}

/// A trait for writing to a GATT characteristic
///
/// Used to abstract the exact mechanism of how writing is performed, whether locally or remotely
/// and whether using BlueZ's Unix domain sockets or the traditional GATT operations on the `Characteristic` types.
pub trait GattCharWrite: Send {
    /// Return the already-negotiated MTU
    fn mtu(&self) -> usize;

    /// Write all the bytes in `data`.
    ///
    /// For the GATT protocol specifically - since it is packetized - ALL of the
    /// data will always be written, as long as it is smaller or equal to the negotiated MTU size.
    /// Otherwise, an error would be returned.
    ///
    /// In general, callers should provide data which is always <= the negotiated MTU size.
    ///
    /// (Ditto for other packetized protocols like UDP.)
    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a;
}

impl<T> GattCharWrite for &mut T
where
    T: GattCharWrite,
{
    fn mtu(&self) -> usize {
        T::mtu(self)
    }

    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        T::write(self, data)
    }
}

/// Implementation of `GattCharRead` for BlueZ's `CharacteristicReader` using Unix domain sockets
impl GattCharRead for CharacteristicReader {
    fn mtu(&self) -> usize {
        CharacteristicReader::mtu(self)
    }

    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        tokio::io::AsyncReadExt::read(self, buf)
    }
}

/// Implementation of `GattCharWrite` for BlueZ's `CharacteristicWriter` using Unix domain sockets
impl GattCharWrite for CharacteristicWriter {
    fn mtu(&self) -> usize {
        CharacteristicWriter::mtu(self)
    }

    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        tokio::io::AsyncWriteExt::write_all(self, data)
    }
}

/// Implementation of `GattCharWrite` for remote GATT characteristics using the traditional GATT operations
///
/// Necessary, because using Unix domain sockets for remote characteristics is not supported by BlueZ
/// for confirmed writes.
pub struct RemoteCharacteristicWriter {
    /// The negotiated MTU
    mtu: usize,
    /// The remote characteristic to write to
    characteristic: RemoteCharacteristic,
    /// The write operation to use
    write_op: WriteOp,
}

impl RemoteCharacteristicWriter {
    /// Create a new `RemoteCharacteristicWriter` for the given remote characteristic
    /// and write operation.
    pub async fn new(
        characteristic: RemoteCharacteristic,
        write_op: WriteOp,
    ) -> Result<Self, std::io::Error> {
        let mtu = characteristic.mtu().await?;

        Ok(Self {
            mtu,
            characteristic,
            write_op,
        })
    }

    /// Write data to the remote characteristic.
    ///
    /// If the size of `data` is greater than the negotiated MTU, a packet truncation IO error
    /// will be returned.
    ///
    /// In general, callers should provide data which is always <= the negotiated MTU size.
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let request = RemoteCharacteristicWriteRequest {
            op_type: self.write_op,
            ..Default::default()
        };

        self.characteristic.write_ext(data, &request).await?;

        Ok(())
    }
}

/// Implementation of `GattCharRead` for remote GATT characteristics using the traditional GATT operations
///
/// Necessary, because using Unix domain sockets for remote characteristics is not supported by BlueZ
/// for indications.
pub struct RemoteCharacteristicReader {
    /// The negotiated MTU
    mtu: usize,
    /// The stream of incoming notifications/indications
    stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>,
}

impl RemoteCharacteristicReader {
    /// Create a new `RemoteCharacteristicReader` for the given remote characteristic.
    pub async fn new(characteristic: RemoteCharacteristic) -> Result<Self, std::io::Error> {
        let mtu = characteristic.mtu().await?;

        let stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>> =
            Box::pin(characteristic.notify().await?);

        Ok(Self { mtu, stream })
    }

    /// Read data from the remote characteristic.
    ///
    /// If the size of `buf` is less than the size of the incoming packet, a packet truncation IO error
    /// will be returned.
    ///
    /// In general, callers should provide a buffer which is always >= the negotiated MTU size.
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if let Some(item) = self.stream.next().await {
            buf[..item.len()].copy_from_slice(&item); // TODO: Check size
            Ok(item.len())
        } else {
            Ok(0)
        }
    }
}

/// Implementation of `GattCharRead` for `RemoteCharacteristicReader`
impl GattCharRead for RemoteCharacteristicReader {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> std::io::Result<usize> {
        RemoteCharacteristicReader::read(self, buf).await
    }
}

/// Implementation of `GattCharWrite` for `RemoteCharacteristicWriter`
impl GattCharWrite for RemoteCharacteristicWriter {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn write<'a>(&'a mut self, data: &'a [u8]) -> std::io::Result<()> {
        RemoteCharacteristicWriter::write(self, data).await
    }
}
