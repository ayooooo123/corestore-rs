//! npm corestore against corestore-rs over secret-stream on TCP.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use corestore::{Corestore, GetOptions};
use hypercore::GetOptions as Get;
use peeroxide_dht::noise::generate_keypair;
use peeroxide_dht::secret_stream::SecretStream;
use protomux::Mux;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::timeout;

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
        .kill_on_drop(true)
        .spawn()
        .expect("node on PATH");
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    (child, lines)
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
            let core = store.namespace("app").get(GetOptions::name(name)).unwrap();
            let blocks: Vec<Vec<u8>> = (0..(10 + i * 7))
                .map(|j| format!("{name}-{j}").into_bytes())
                .collect();
            core.append(&blocks).await.unwrap();
            expected.push((hex(core.key()), blocks));
        }
    }
    // Reopened with nothing open: every core opens because JS asks for it.
    // Background replicator tasks of the first instance may still hold the
    // database for a moment after it is dropped.
    let store = loop {
        match Corestore::open(&tmp.path().join("rust")) {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let js = tmp.path().join("js");
    let mut args = vec!["read", js.to_str().unwrap(), &port];
    let keys: Vec<String> = expected.iter().map(|(k, _)| k.clone()).collect();
    args.extend(keys.iter().map(String::as_str));
    let (_child, mut out) = node(&args);
    let (tcp, _) = listener.accept().await.unwrap();
    let mux = Mux::from_secret_stream(
        SecretStream::new(false, tcp, generate_keypair())
            .await
            .unwrap(),
    );
    store.replicate(&mux);
    for (key, blocks) in &expected {
        let report = timeout(Duration::from_secs(30), line(&mut out, "core "))
            .await
            .expect("JS read timed out");
        assert_eq!(report, format!("{key} {} {}", blocks.len(), sha256(blocks)));
    }
    assert_eq!(store.open_cores().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs node and `npm install` in tests/js"]
async fn rust_reads_a_js_corestore_core() {
    let tmp = tempfile::tempdir().unwrap();
    let js = tmp.path().join("js");
    let (_child, mut out) = node(&["write", js.to_str().unwrap(), "feed"]);
    let key: [u8; 32] = {
        let h = line(&mut out, "key ").await;
        (0..32)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    let port = line(&mut out, "port ").await;
    let store = Corestore::open(&tmp.path().join("rust")).unwrap();
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let mux = Mux::from_secret_stream(
        SecretStream::new(true, tcp, generate_keypair())
            .await
            .unwrap(),
    );
    store.replicate(&mux);
    let core = store.get(GetOptions::key(key)).unwrap();
    assert!(
        timeout(Duration::from_secs(30), core.update(None))
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
    mux.destroy();
}
