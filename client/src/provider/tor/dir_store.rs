//! In-memory `tor_dirmgr::storage::Store` impl, backed by `HashMap`s.
//!
//! `arti`'s default dir store is sqlite-backed via `rusqlite`, which doesn't
//! work on `wasm32-unknown-unknown` (no real filesystem). This implementation
//! keeps everything in process memory; the cache is lost when the page is
//! reloaded but is rebuilt during the next bootstrap.
//!
//! No expiration is enforced — `expire_all` is a no-op. All entries persist
//! until the store is dropped.

use std::{collections::HashMap, sync::Mutex, time::SystemTime};

use arti_client::{DirMgrStoreBuilder, ErrorDetail};
use tor_dirmgr::{
	DirMgrConfig, DirMgrStore,
	docmeta::{AuthCertMeta, ConsensusMeta},
	storage::{CachedBridgeDescriptor, DynStore, ExpirationConfig, InputString, Store},
};
use tor_guardmgr::bridge::BridgeConfig;
use tor_netdoc::doc::{
	authcert::AuthCertKeyIds,
	microdesc::MdDigest,
	netstatus::{ConsensusFlavor, ProtoStatuses},
	routerdesc::RdDigest,
};
use tor_rtcompat::Runtime;

type DirResult<T> = Result<T, tor_dirmgr::Error>;

/// In-memory snapshot of all the directory state arti can persist.
#[derive(Default)]
struct WasmDirStoreInner {
	consensus: HashMap<ConsensusFlavor, ConsensusEntry>,
	authcerts: HashMap<AuthCertKeyIds, String>,
	microdescs: HashMap<MdDigest, String>,
	routerdescs: HashMap<RdDigest, String>,
	bridgedescs: HashMap<BridgeConfig, CachedBridgeDescriptor>,
	protocol_recs: Option<(SystemTime, ProtoStatuses)>,
}

struct ConsensusEntry {
	contents: String,
	meta: ConsensusMeta,
	pending: bool,
}

pub struct WasmDirStore {
	inner: Mutex<WasmDirStoreInner>,
}

impl WasmDirStore {
	pub fn new() -> Self {
		Self {
			inner: Mutex::new(WasmDirStoreInner::default()),
		}
	}
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
	m.lock().expect("WasmDirStore mutex poisoned")
}

impl Store for WasmDirStore {
	fn is_readonly(&self) -> bool {
		false
	}

	fn upgrade_to_readwrite(&mut self) -> DirResult<bool> {
		Ok(true)
	}

	fn expire_all(&mut self, _expiration: &ExpirationConfig) -> DirResult<()> {
		// In-memory cache; nothing to expire here.
		Ok(())
	}

	fn latest_consensus(
		&self,
		flavor: ConsensusFlavor,
		pending: Option<bool>,
	) -> DirResult<Option<InputString>> {
		let g = lock(&self.inner);
		let Some(entry) = g.consensus.get(&flavor) else {
			return Ok(None);
		};
		if let Some(want_pending) = pending {
			if entry.pending != want_pending {
				return Ok(None);
			}
		}
		Ok(Some(InputString::Utf8(entry.contents.clone())))
	}

	fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> DirResult<Option<ConsensusMeta>> {
		let g = lock(&self.inner);
		Ok(g.consensus.get(&flavor).and_then(|entry| {
			if entry.pending {
				None
			} else {
				Some(entry.meta.clone())
			}
		}))
	}

	fn consensus_by_sha3_digest_of_signed_part(
		&self,
		d: &[u8; 32],
	) -> DirResult<Option<(InputString, ConsensusMeta)>> {
		let g = lock(&self.inner);
		for entry in g.consensus.values() {
			if entry.meta.sha3_256_of_signed() == d {
				return Ok(Some((
					InputString::Utf8(entry.contents.clone()),
					entry.meta.clone(),
				)));
			}
		}
		Ok(None)
	}

	fn store_consensus(
		&mut self,
		cmeta: &ConsensusMeta,
		flavor: ConsensusFlavor,
		pending: bool,
		contents: &str,
	) -> DirResult<()> {
		lock(&self.inner).consensus.insert(
			flavor,
			ConsensusEntry {
				contents: contents.to_owned(),
				meta: cmeta.clone(),
				pending,
			},
		);
		Ok(())
	}

	fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> DirResult<()> {
		let mut g = lock(&self.inner);
		for entry in g.consensus.values_mut() {
			if entry.meta.sha3_256_of_signed() == cmeta.sha3_256_of_signed() {
				entry.pending = false;
			}
		}
		Ok(())
	}

	fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> DirResult<()> {
		let mut g = lock(&self.inner);
		g.consensus.retain(|_, entry| {
			entry.meta.sha3_256_of_signed() != cmeta.sha3_256_of_signed()
		});
		Ok(())
	}

	fn authcerts(
		&self,
		certs: &[AuthCertKeyIds],
	) -> DirResult<HashMap<AuthCertKeyIds, String>> {
		let g = lock(&self.inner);
		let mut out = HashMap::with_capacity(certs.len());
		for id in certs {
			if let Some(text) = g.authcerts.get(id) {
				out.insert(*id, text.clone());
			}
		}
		Ok(out)
	}

	fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> DirResult<()> {
		let mut g = lock(&self.inner);
		for (meta, text) in certs {
			g.authcerts.insert(*meta.key_ids(), (*text).to_owned());
		}
		Ok(())
	}

	fn microdescs(&self, digests: &[MdDigest]) -> DirResult<HashMap<MdDigest, String>> {
		let g = lock(&self.inner);
		let mut out = HashMap::with_capacity(digests.len());
		for d in digests {
			if let Some(text) = g.microdescs.get(d) {
				out.insert(*d, text.clone());
			}
		}
		Ok(out)
	}

	fn store_microdescs(
		&mut self,
		digests: &[(&str, &MdDigest)],
		_when: SystemTime,
	) -> DirResult<()> {
		let mut g = lock(&self.inner);
		for (text, digest) in digests {
			g.microdescs.insert(**digest, (*text).to_owned());
		}
		Ok(())
	}

	fn update_microdescs_listed(
		&mut self,
		_digests: &[MdDigest],
		_when: SystemTime,
	) -> DirResult<()> {
		// No expiration tracking — nothing to refresh.
		Ok(())
	}

	fn routerdescs(&self, digests: &[RdDigest]) -> DirResult<HashMap<RdDigest, String>> {
		let g = lock(&self.inner);
		let mut out = HashMap::with_capacity(digests.len());
		for d in digests {
			if let Some(text) = g.routerdescs.get(d) {
				out.insert(*d, text.clone());
			}
		}
		Ok(out)
	}

	fn store_routerdescs(
		&mut self,
		digests: &[(&str, SystemTime, &RdDigest)],
	) -> DirResult<()> {
		let mut g = lock(&self.inner);
		for (text, _published, digest) in digests {
			g.routerdescs.insert(**digest, (*text).to_owned());
		}
		Ok(())
	}

	fn lookup_bridgedesc(&self, bridge: &BridgeConfig) -> DirResult<Option<CachedBridgeDescriptor>> {
		Ok(lock(&self.inner).bridgedescs.get(bridge).cloned())
	}

	fn store_bridgedesc(
		&mut self,
		bridge: &BridgeConfig,
		entry: CachedBridgeDescriptor,
		_until: SystemTime,
	) -> DirResult<()> {
		lock(&self.inner).bridgedescs.insert(bridge.clone(), entry);
		Ok(())
	}

	fn delete_bridgedesc(&mut self, bridge: &BridgeConfig) -> DirResult<()> {
		lock(&self.inner).bridgedescs.remove(bridge);
		Ok(())
	}

	fn update_protocol_recommendations(
		&mut self,
		valid_after: SystemTime,
		protocols: &ProtoStatuses,
	) -> DirResult<()> {
		lock(&self.inner).protocol_recs = Some((valid_after, protocols.clone()));
		Ok(())
	}

	fn cached_protocol_recommendations(
		&self,
	) -> DirResult<Option<(SystemTime, ProtoStatuses)>> {
		Ok(lock(&self.inner).protocol_recs.clone())
	}
}

pub(crate) struct WasmDirStoreBuilder;

impl<R: Runtime> DirMgrStoreBuilder<R> for WasmDirStoreBuilder {
	fn build(
		&self,
		runtime: R,
		_config: &DirMgrConfig,
		_offline: bool,
	) -> Result<DirMgrStore<R>, ErrorDetail> {
		let store: DynStore = Box::new(WasmDirStore::new());
		Ok(DirMgrStore::from_store(store, runtime))
	}
}
