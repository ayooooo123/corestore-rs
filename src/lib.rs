#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use blake2b_simd::Params;
use hypercore::crypto::{self, KeyPair};
use hypercore::encryption::EncryptionOptions;
use hypercore::replicator::PROTOCOL;
use hypercore::storage::{StorageError, Store};
use hypercore::{Core, CoreError, CoreOptions, Manifest, Session};
use protomux::Mux;
use tokio::sync::mpsc;

/// JS `DEFAULT_NAMESPACE`: 32 zero bytes.
pub const DEFAULT_NAMESPACE: [u8; 32] = [0; 32];
const PRIMARY_KEY: &str = "corestore/primary-key";
/// JS strikes an idle core every 2 s and closes it on the fourth strike.
const GC_INTERVAL: Duration = Duration::from_secs(2);
const GC_STRIKES: u8 = 4;

#[derive(Debug)]
pub enum Error {
    Core(CoreError),
    Storage(StorageError),
    /// The directory belongs to a corestore with another primary key.
    OtherCorestore,
    /// `get` needs a name, key, key pair, manifest or discovery key.
    NoKey,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Core(e) => write!(f, "{e}"),
            Error::Storage(e) => write!(f, "{e}"),
            Error::OtherCorestore => f.write_str("Another corestore is stored here"),
            Error::NoKey => f.write_str("Could not derive discovery from input"),
        }
    }
}

impl std::error::Error for Error {}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Core(e)
    }
}

impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        Error::Storage(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

fn hash(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).key(key).to_state();
    for p in parts {
        h.update(p);
    }
    h.finalize().as_bytes().try_into().expect("32 bytes")
}

/// JS `generateNamespace(namespace, name)`.
pub fn namespace_of(parent: &[u8; 32], name: &[u8]) -> [u8; 32] {
    hash(&[], &[parent, name])
}

/// JS `createKeyPair(primaryKey, namespace, name)`.
pub fn derive_key_pair(primary_key: &[u8; 32], namespace: &[u8; 32], name: &[u8]) -> KeyPair {
    let ns = crypto::namespace(b"corestore", 1)[0];
    KeyPair::from_seed(&hash(primary_key, &[&ns, namespace, name]))
}

/// What to open. Mirrors the options of JS `store.get()`.
#[derive(Default, Clone)]
pub struct GetOptions {
    pub name: Option<Vec<u8>>,
    pub key: Option<[u8; 32]>,
    pub discovery_key: Option<[u8; 32]>,
    pub key_pair: Option<KeyPair>,
    pub manifest: Option<Manifest>,
    pub encryption_key: Option<[u8; 32]>,
    pub encryption: EncryptionOptions,
    /// Open a session that does not keep the core downloading.
    pub inactive: bool,
}

impl GetOptions {
    pub fn name(name: impl Into<Vec<u8>>) -> Self {
        Self {
            name: Some(name.into()),
            ..Default::default()
        }
    }

    pub fn key(key: [u8; 32]) -> Self {
        Self {
            key: Some(key),
            ..Default::default()
        }
    }
}

struct Root {
    store: Store,
    primary_key: [u8; 32],
    cores: Mutex<HashMap<[u8; 32], Core>>,
    muxes: Mutex<Vec<Mux>>,
    watchers: Mutex<Vec<mpsc::UnboundedSender<Core>>>,
    gc: Mutex<HashMap<[u8; 32], u8>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A set of cores in one storage directory, replicated together. Cheap to
/// clone; `namespace()` gives a view whose names derive other keys.
#[derive(Clone)]
pub struct Corestore {
    root: Arc<Root>,
    ns: [u8; 32],
}

impl Corestore {
    /// Opens the corestore in `dir`, creating a random primary key the first time.
    pub fn open(dir: &Path) -> Result<Corestore> {
        Self::open_with(dir, None)
    }

    /// Opens with a known primary key (JS `primaryKey` with `unsafe: true`).
    pub fn open_with_primary_key(dir: &Path, primary_key: [u8; 32]) -> Result<Corestore> {
        Self::open_with(dir, Some(primary_key))
    }

    fn open_with(dir: &Path, wanted: Option<[u8; 32]>) -> Result<Corestore> {
        let store = Store::open(dir)?;
        let primary_key = match store.get_meta(PRIMARY_KEY)? {
            Some(stored) => {
                let stored: [u8; 32] = stored[..].try_into().map_err(|_| Error::OtherCorestore)?;
                if wanted.is_some_and(|w| w != stored) {
                    return Err(Error::OtherCorestore);
                }
                stored
            }
            None => {
                let pk = wanted.unwrap_or_else(rand::random);
                store.put_meta(PRIMARY_KEY, Some(&pk))?;
                pk
            }
        };
        let root = Root {
            store,
            primary_key,
            cores: Mutex::default(),
            muxes: Mutex::default(),
            watchers: Mutex::default(),
            gc: Mutex::default(),
        };
        Ok(Corestore {
            root: Arc::new(root),
            ns: DEFAULT_NAMESPACE,
        })
    }

    pub fn primary_key(&self) -> &[u8; 32] {
        &self.root.primary_key
    }

    pub fn namespace_key(&self) -> &[u8; 32] {
        &self.ns
    }

    /// A view in the child namespace `name` (JS `store.namespace(name)`).
    pub fn namespace(&self, name: impl AsRef<[u8]>) -> Corestore {
        Corestore {
            root: self.root.clone(),
            ns: namespace_of(&self.ns, name.as_ref()),
        }
    }

    /// JS `store.createKeyPair(name)`.
    pub fn create_key_pair(&self, name: impl AsRef<[u8]>) -> KeyPair {
        derive_key_pair(&self.root.primary_key, &self.ns, name.as_ref())
    }

    /// Opens (or creates) a core and returns a session on it.
    pub fn get(&self, opts: GetOptions) -> Result<Session> {
        let key_pair = match &opts.name {
            Some(name) => Some(self.create_key_pair(name)),
            None => opts.key_pair.clone(),
        };
        let manifest = opts.manifest.clone().or_else(|| {
            key_pair
                .as_ref()
                .map(|kp| hypercore::verifier::default_signer_manifest(kp.public_key))
        });
        let key = opts
            .key
            .or_else(|| manifest.as_ref().map(crypto::manifest_hash));
        let dk = match (key, opts.discovery_key) {
            (Some(k), _) => crypto::discovery_key(&k),
            (None, Some(dk)) => dk,
            (None, None) => return Err(Error::NoKey),
        };
        if let Some(core) = self.resume(&dk) {
            return Ok(core.session(!opts.inactive));
        }
        let core_opts = CoreOptions {
            key,
            key_pair,
            manifest,
            encryption_key: opts.encryption_key,
            encryption: opts.encryption,
            no_create: key.is_none(),
        };
        let core = match key {
            Some(_) => Core::open(&self.root.store, core_opts)?,
            None => Core::open_by_discovery_key(&self.root.store, &dk, core_opts)?,
        };
        let core = self.root.register(core);
        Ok(core.session(!opts.inactive))
    }

    /// An open core, also reviving one waiting to be garbage collected.
    fn resume(&self, dk: &[u8; 32]) -> Option<Core> {
        let core = lock(&self.root.cores).get(dk).cloned()?;
        lock(&self.root.gc).remove(dk);
        Some(core)
    }

    /// Cores opened from now on, as they open (JS `store.watch`).
    pub fn watch(&self) -> mpsc::UnboundedReceiver<Core> {
        let (tx, rx) = mpsc::unbounded_channel();
        lock(&self.root.watchers).push(tx);
        rx
    }

    /// Discovery keys of every stored core.
    pub fn list(&self) -> Result<Vec<[u8; 32]>> {
        Ok(self.root.store.cores()?)
    }

    /// Cores currently open.
    pub fn open_cores(&self) -> Vec<Core> {
        lock(&self.root.cores).values().cloned().collect()
    }

    /// Replicates every open core over `mux`, and opens stored cores on
    /// demand when the remote asks for them by discovery key.
    pub fn replicate(&self, mux: &Mux) {
        {
            let mut muxes = lock(&self.root.muxes);
            muxes.retain(|m| !m.is_destroyed());
            muxes.push(mux.clone());
        }
        for core in self.open_cores() {
            core.replicate(mux);
        }
        let mut requests = mux.pair(PROTOCOL, None);
        let root = Arc::downgrade(&self.root);
        let mux = mux.clone();
        tokio::spawn(async move {
            while let Some(req) = requests.recv().await {
                let Some(root) = root.upgrade() else { break };
                root.on_pair_request(&mux, req);
            }
        });
    }

    /// Deletes a stored core unless something still uses it (JS `store.purge`).
    pub async fn purge(&self, discovery_key: &[u8; 32]) -> Result<bool> {
        let core = match self.resume(discovery_key) {
            Some(c) => c,
            None => match Core::open_by_discovery_key(
                &self.root.store,
                discovery_key,
                CoreOptions::default(),
            ) {
                Ok(c) => c,
                Err(CoreError::NotFound) => return Ok(false),
                Err(e) => return Err(e.into()),
            },
        };
        if core.active_session_count() > 0 {
            return Ok(false);
        }
        lock(&self.root.cores).remove(discovery_key);
        lock(&self.root.gc).remove(discovery_key);
        core.close();
        core.purge().await?;
        Ok(true)
    }
}

impl Root {
    fn register(self: &Arc<Self>, core: Core) -> Core {
        let dk = *core.discovery_key();
        let core = {
            let mut cores = lock(&self.cores);
            if let Some(existing) = cores.get(&dk) {
                return existing.clone();
            }
            cores.insert(dk, core.clone());
            core
        };
        let root = Arc::downgrade(self);
        core.set_idle_hook(move |c| {
            if let Some(root) = root.upgrade() {
                root.strike(*c.discovery_key());
            }
        });
        lock(&self.watchers).retain(|w| w.send(core.clone()).is_ok());
        let muxes: Vec<Mux> = lock(&self.muxes)
            .iter()
            .filter(|m| !m.is_destroyed())
            .cloned()
            .collect();
        for mux in muxes {
            core.replicate(&mux);
        }
        core
    }

    fn on_pair_request(self: &Arc<Self>, mux: &Mux, req: protomux::PairRequest) {
        let Some(dk) = req
            .id
            .as_deref()
            .and_then(|id| <[u8; 32]>::try_from(id).ok())
        else {
            return;
        };
        let open = lock(&self.cores).get(&dk).cloned();
        let core = match open {
            Some(c) => {
                lock(&self.gc).remove(&dk);
                c
            }
            None => match Core::open_by_discovery_key(&self.store, &dk, CoreOptions::default()) {
                Ok(c) => self.register(c),
                Err(_) => return, // not stored here: the remote open is rejected
            },
        };
        core.replicate_paired(mux, req);
    }

    /// First strike for a core that went idle; starts the sweep if needed.
    fn strike(self: &Arc<Self>, dk: [u8; 32]) {
        let mut gc = lock(&self.gc);
        if gc.contains_key(&dk) || !lock(&self.cores).contains_key(&dk) {
            return;
        }
        gc.insert(dk, 1);
        if gc.len() == 1 {
            tokio::spawn(sweep(Arc::downgrade(self)));
        }
    }
}

/// Runs only while cores await collection, like the JS gc interval.
async fn sweep(root: Weak<Root>) {
    loop {
        tokio::time::sleep(GC_INTERVAL).await;
        let Some(root) = root.upgrade() else { return };
        let mut gc = lock(&root.gc);
        let mut cores = lock(&root.cores);
        gc.retain(|dk, strikes| {
            let Some(core) = cores.get(dk) else {
                return false;
            };
            // Spare a core that has a session or a peer again (the gc fix).
            if !core.is_idle() {
                return false;
            }
            *strikes += 1;
            if *strikes < GC_STRIKES {
                return true;
            }
            core.close();
            cores.remove(dk);
            false
        });
        if gc.is_empty() {
            return;
        }
    }
}
