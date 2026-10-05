//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

use std::{fmt, str::FromStr, sync::Arc};

use async_trait::async_trait;
use iroh::{
    endpoint::{Connection, RecvStream, SendStream, VarInt},
    EndpointAddr, EndpointId,
};
#[cfg(all(feature = "uring", target_os = "linux"))]
use std::os::fd::RawFd;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use zenoh_core::zasynclock;

use zenoh_link_commons::{
    LinkAuthId, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
use zenoh_result::{bail, zerror, ZResult};

use crate::{locator_of, IrohEndpoint, ALPN, IROH_MAX_MTU};

pub struct LinkUnicastIroh {
    connection: Connection,
    src_locator: Locator,
    dst_locator: Locator,
    send: AsyncMutex<SendStream>,
    recv: AsyncMutex<RecvStream>,
    auth_id: LinkAuthId,
}

impl LinkUnicastIroh {
    fn new(local: EndpointId, connection: Connection, send: SendStream, recv: RecvStream) -> Self {
        let remote = connection.remote_id();
        Self {
            src_locator: locator_of(&local),
            dst_locator: locator_of(&remote),
            auth_id: LinkAuthId::Iroh(remote.to_string()),
            connection,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastIroh {
    async fn close(&self) -> ZResult<()> {
        tracing::trace!("Closing iroh link: {}", self);
        if let Err(e) = zasynclock!(self.send).finish() {
            tracing::trace!("Error finishing iroh stream {}: {}", self, e);
        }
        self.connection.close(VarInt::from_u32(0), b"");
        Ok(())
    }

    // One stream per link: priorities are not separated (`supports_priorities` keeps its default, false).
    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.send)
            .write(buffer)
            .await
            .map_err(|e| zerror!("Write error on iroh link {}: {}", self, e).into())
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.send)
            .write_all(buffer)
            .await
            .map_err(|e| zerror!("Write error on iroh link {}: {}", self, e).into())
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.recv)
            .read(buffer)
            .await
            .map_err(|e| zerror!("Read error on iroh link {}: {}", self, e))?
            .ok_or_else(|| zerror!("Read error on iroh link {}: stream closed", self).into())
    }

    async fn read_exact(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.recv)
            .read_exact(buffer)
            .await
            .map_err(|e| zerror!("Read error on iroh link {}: {}", self, e).into())
    }

    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    fn get_mtu(&self) -> BatchSize {
        IROH_MAX_MTU
    }

    fn get_interface_names(&self) -> Vec<String> {
        vec![]
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn is_streamed(&self) -> bool {
        true
    }

    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    #[cfg(all(feature = "uring", target_os = "linux"))]
    fn get_fd(&self) -> ZResult<RawFd> {
        bail!("Not supported");
    }
}

impl Drop for LinkUnicastIroh {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"");
    }
}

impl fmt::Display for LinkUnicastIroh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_locator, self.dst_locator)
    }
}

impl fmt::Debug for LinkUnicastIroh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iroh")
            .field("src", &self.src_locator)
            .field("dst", &self.dst_locator)
            .finish()
    }
}

struct Listener {
    endpoint: EndPoint,
    locator: Locator,
    token: CancellationToken,
}

pub struct LinkManagerUnicastIroh {
    manager: NewLinkChannelSender,
    iroh: IrohEndpoint,
    listener: std::sync::Mutex<Option<Listener>>,
}

impl LinkManagerUnicastIroh {
    pub fn new(manager: NewLinkChannelSender, iroh: IrohEndpoint) -> Self {
        Self {
            manager,
            iroh,
            listener: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastIroh {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let addr = endpoint.address();
        let id = EndpointId::from_str(addr.as_str())
            .map_err(|e| zerror!("invalid iroh endpoint id {}: {}", addr, e))?;
        let connection = self
            .iroh
            .endpoint()
            .connect(EndpointAddr::new(id), ALPN)
            .await
            .map_err(|e| zerror!("Cannot connect to iroh endpoint {}: {}", id, e))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| zerror!("Cannot open iroh stream to {}: {}", id, e))?;
        let link: Arc<dyn LinkUnicastTrait> =
            Arc::new(LinkUnicastIroh::new(self.iroh.id(), connection, send, recv));
        Ok(LinkUnicast::from(link))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let own = self.iroh.id();
        let addr = endpoint.address();
        if addr.as_str() != crate::IROH_LISTEN_AUTO && addr.as_str() != own.to_string() {
            bail!(
                "iroh listener address must be `{}` or this endpoint's id ({own}), got {addr}",
                crate::IROH_LISTEN_AUTO
            );
        }
        let mut guard = self.listener.lock().unwrap();
        if guard.is_some() {
            bail!("already listening on iroh as {own}");
        }
        let locator = Locator::new(
            crate::IROH_LOCATOR_PREFIX,
            own.to_string(),
            endpoint.metadata(),
        )?;
        let token = CancellationToken::new();
        zenoh_runtime::ZRuntime::Acceptor.spawn(accept_task(
            self.iroh.clone(),
            self.manager.clone(),
            token.clone(),
        ));
        *guard = Some(Listener {
            endpoint,
            locator: locator.clone(),
            token,
        });
        Ok(locator)
    }

    async fn del_listener(&self, _endpoint: &EndPoint) -> ZResult<()> {
        match self.listener.lock().unwrap().take() {
            Some(l) => {
                l.token.cancel();
                Ok(())
            }
            None => bail!("not listening on iroh"),
        }
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        self.listener
            .lock()
            .unwrap()
            .iter()
            .map(|l| l.endpoint.clone())
            .collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        self.listener
            .lock()
            .unwrap()
            .iter()
            .map(|l| l.locator.clone())
            .collect()
    }

    /// iroh locators carry no IP address, so there is no loopback to filter out.
    async fn get_locators_noloopback(&self) -> Vec<Locator> {
        self.get_locators().await
    }
}

async fn accept_task(iroh: IrohEndpoint, manager: NewLinkChannelSender, token: CancellationToken) {
    tracing::trace!("Ready to accept iroh connections as {}", iroh.id());
    loop {
        let incoming = tokio::select! {
            _ = token.cancelled() => break,
            incoming = iroh.endpoint().accept() => match incoming {
                Some(incoming) => incoming,
                None => break, // endpoint closed
            },
        };
        let (iroh, manager) = (iroh.clone(), manager.clone());
        zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
            let result: ZResult<()> = async {
                let connection = incoming
                    .accept()
                    .map_err(|e| zerror!("{e}"))?
                    .await
                    .map_err(|e| zerror!("{e}"))?;
                let (send, recv) = connection.accept_bi().await.map_err(|e| zerror!("{e}"))?;
                let link = LinkUnicastIroh::new(iroh.id(), connection, send, recv);
                tracing::debug!("Accepted iroh connection: {}", link);
                let link: Arc<dyn LinkUnicastTrait> = Arc::new(link);
                manager
                    .send_async(LinkUnicast::from(link))
                    .await
                    .map_err(|e| zerror!("{e}").into())
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("Failed to accept iroh connection: {}", e);
            }
        });
    }
}
