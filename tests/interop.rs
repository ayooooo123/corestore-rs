//! npm corestore against corestore-rs over Hyperswarm/peeroxide on a local
//! HyperDHT testnet: holepunch handshake, UDX, secret-stream, as apps run.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use corestore::{Corestore, GetOptions};
use hypercore::GetOptions as Get;
use peeroxide::{JoinOpts, SwarmConfig, SwarmHandle, spawn};
use peeroxide_dht::hyperdht::HyperDhtConfig;
use peeroxide_dht::rpc::DhtConfig;
use protomux::Mux;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::timeout;

const TOPIC: [u8; 32] = [0x5c; 32];

fn node(args: &[&str]) -> (Child, Lines<BufReader<ChildStdout>>) {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js"));
    assert!(
        dir.join("node_modules").exists(),
        "run `npm install` in {}",
        dir.display()
    );
    let mut child = Command::new("node")
        .arg("peer.js")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("node on PATH");
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    (child, lines)
}

/// A peeroxide swarm on the testnet that replicates `store` on every connection.
async fn swarm(port: &str, store: &Corestore, client: bool) -> SwarmHandle {
    let mut dht = DhtConfig::default();
    dht.bootstrap = vec![format!("127.0.0.1:{port}")];
    dht.host = "127.0.0.1".into();
    dht.port = 0;
    let mut hyper = HyperDhtConfig::default();
    hyper.dht = dht;
    let mut config = SwarmConfig::default();
    config.dht = hyper;
    let (_task, handle, mut conns) = spawn(config).await.expect("peeroxide swarm");
    let store = store.clone();
    tokio::spawn(async move {
        while let Some(conn) = conns.recv().await {
            store.replicate(&Mux::from_secret_stream(conn.peer.stream));
        }
    });
    let mut opts = JoinOpts::default();
    opts.client = client;
    opts.server = !client;
    handle.join(TOPIC, opts).await.unwrap();
    if !client {
        handle.flush().await.unwrap();
    }
    handle
}

async fn line(out: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    loop {
        let l = out
            .next_line()
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("node exited before {prefix:?}"));
        assert!(!l.starts_with("error"), "{l}");
        if let Some(rest) = l.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256(blocks: &[Vec<u8>]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for b in blocks {
        h.update(b);
    }
    hex(&h.finalize())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn js_reads_any_stored_rust_core() {
    let tmp = tempfile::tempdir().unwrap();
    let mut expected = vec![];
    {
        let store = Corestore::open(&tmp.path().join("rust")).unwrap();
        for (i, name) in ["main", "video-blobs", "comments"].into_iter().enumerate() {
            let core = store
                .namespace("app")
                .get(GetOptions::name(name))
                .await
                .unwrap();
            let blocks: Vec<Vec<u8>> = (0..(10 + i * 7))
                .map(|j| format!("{name}-{j}").into_bytes())
                .collect();
            core.append(&blocks).await.unwrap();
            expected.push((hex(core.key()), blocks));
        }
        store.close().await;
    }
    // Reopened with nothing open: every core opens because JS asks for it.
    let store = Corestore::open(&tmp.path().join("rust")).unwrap();
    let (_testnet, mut tn) = node(&["testnet"]);
    let port = line(&mut tn, "bootstrap ").await;
    let swarm = swarm(&port, &store, false).await;
    let js = tmp.path().join("js");
    let topic = hex(&TOPIC);
    let mut args = vec!["read", js.to_str().unwrap(), &port, &topic];
    let keys: Vec<String> = expected.iter().map(|(k, _)| k.clone()).collect();
    args.extend(keys.iter().map(String::as_str));
    let (_child, mut out) = node(&args);
    for (key, blocks) in &expected {
        let report = timeout(Duration::from_secs(60), line(&mut out, "core "))
            .await
            .expect("JS read timed out");
        assert_eq!(report, format!("{key} {} {}", blocks.len(), sha256(blocks)));
    }
    assert_eq!(store.open_cores().len(), 3);
    let _ = swarm.destroy().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn rust_reads_a_js_corestore_core() {
    let tmp = tempfile::tempdir().unwrap();
    let (_testnet, mut tn) = node(&["testnet"]);
    let port = line(&mut tn, "bootstrap ").await;
    let js = tmp.path().join("js");
    let (_child, mut out) = node(&["write", js.to_str().unwrap(), &port, &hex(&TOPIC), "feed"]);
    let key: [u8; 32] = {
        let h = line(&mut out, "key ").await;
        (0..32)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    line(&mut out, "ready").await;
    let store = Corestore::open(&tmp.path().join("rust")).unwrap();
    let swarm = swarm(&port, &store, true).await;
    let core = store.get(GetOptions::key(key)).await.unwrap();
    assert!(
        timeout(Duration::from_secs(60), core.update(None))
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(core.length(), 50);
    for i in 0..50 {
        let b = timeout(Duration::from_secs(10), core.get(i, Get::default()))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(b, format!("js-block-{i}").into_bytes());
    }
    let _ = swarm.destroy().await;
}
