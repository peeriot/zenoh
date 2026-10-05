use iroh::{
    address_lookup::{DnsAddressLookup, MemoryLookup, PkarrResolver},
    endpoint::{default_relay_mode, presets},
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
};
use zenoh_result::{zerror, ZResult};

use crate::ALPN;

pub struct IrohEndpointConfig {
    pub secret_key: SecretKey,
    /// n0 relays and n0 DNS resolution when true; direct addresses only when false.
    /// Never publishes this endpoint's addresses anywhere.
    pub relays: bool,
}

/// The iroh endpoint of one zenoh runtime, shared by the iroh link manager and zone discovery.
#[derive(Clone, Debug)]
pub struct IrohEndpoint {
    endpoint: Endpoint,
    memory: MemoryLookup,
}

impl IrohEndpoint {
    pub async fn bind(cfg: IrohEndpointConfig) -> ZResult<Self> {
        let memory = MemoryLookup::new();
        // `presets::N0` minus `PkarrPublisher`: discovery happens on the zone topic, so
        // nothing is published to n0 DNS.
        let mut builder = Endpoint::builder(presets::Minimal);
        builder = if cfg.relays {
            builder
                .relay_mode(default_relay_mode())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns())
        } else {
            builder.relay_mode(RelayMode::Disabled)
        };
        let endpoint = builder
            .secret_key(cfg.secret_key)
            .alpns(vec![ALPN.to_vec()])
            .address_lookup(memory.clone())
            .bind()
            .await
            .map_err(|e| zerror!("Cannot bind iroh endpoint: {e}"))?;
        tracing::info!("iroh endpoint {} bound", endpoint.id());
        Ok(Self { endpoint, memory })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Replace what is known about `addr.id`, so a dial by id alone uses these addresses.
    pub fn set_addr(&self, addr: EndpointAddr) {
        self.memory.set_endpoint_info(addr);
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}
