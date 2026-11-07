use std::time::Duration;

use corestore::{Corestore, GetOptions};
use hypercore::GetOptions as Get;
use protomux::{Mux, StreamInfo, memory};
use serde_json::Value;
use tokio::time::timeout;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test]
async fn keys_match_js_corestore() {
    let fixture: Vec<Value> = serde_json::from_str(include_str!("../fixtures/keys.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = Corestore::open_with_primary_key(dir.path(), [7; 32]).unwrap();
    for case in &fixture {
        let mut view = root.clone();
        match case["path"].as_str().unwrap() {
            "" => {}
            "bytes" => view = view.namespace([0u8, 1, 2, 255]),
            path => {
                for part in path.split('/') {
                    view = view.namespace(part);
                }
            }
        }
        let name = case["name"].as_str().unwrap();
        let kp = view.create_key_pair(name);
        assert_eq!(
            hex(&kp.public_key),
            case["publicKey"].as_str().unwrap(),
            "{case}"
        );
        let core = view.get(GetOptions::name(name)).await.unwrap();
        assert_eq!(hex(core.key()), case["key"].as_str().unwrap(), "{case}");
        assert_eq!(
            hex(core.discovery_key()),
            case["discoveryKey"].as_str().unwrap(),
            "{case}"
        );
        assert!(core.writable());
    }
    drop(root);
    assert!(matches!(
        Corestore::open_with_primary_key(dir.path(), [8; 32]),
        Err(corestore::Error::OtherCorestore)
    ));
}

#[tokio::test]
async fn reopening_keeps_the_primary_key_and_cores() {
    let dir = tempfile::tempdir().unwrap();
    let (pk, key) = {
        let store = Corestore::open(dir.path()).unwrap();
        let core = store.get(GetOptions::name("x")).await.unwrap();
        core.append(&[b"hi".as_slice()]).await.unwrap();
        (*store.primary_key(), *core.key())
    };
    let store = Corestore::open(dir.path()).unwrap();
    assert_eq!(store.primary_key(), &pk);
    let core = store.get(GetOptions::name("x")).await.unwrap();
    assert_eq!(core.key(), &key);
    assert_eq!(core.length(), 1);
    let by_dk = store
        .get(GetOptions {
            discovery_key: Some(*core.discovery_key()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        by_dk.key(),
        &key,
        "opening by discovery key finds the stored core"
    );
    assert_eq!(store.list().unwrap(), vec![*core.discovery_key()]);
}

#[tokio::test]
async fn watch_reports_new_cores() {
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let mut watch = store.watch();
    let a = store.get(GetOptions::name("a")).await.unwrap();
    let _again = store.get(GetOptions::name("a")).await.unwrap();
    let b = store
        .namespace("ns")
        .get(GetOptions::name("a"))
        .await
        .unwrap();
    assert_eq!(watch.recv().await.unwrap().key(), a.key());
    assert_eq!(watch.recv().await.unwrap().key(), b.key());
    assert!(
        watch.try_recv().is_err(),
        "reopening an open core is not a new core"
    );
    assert_ne!(a.key(), b.key(), "namespaces derive different keys");
}

fn link() -> (Mux, Mux) {
    let ((ar, aw), (br, bw)) = memory::duplex(64);
    let hh = Some([3u8; 64]);
    (
        Mux::new(
            ar,
            aw,
            StreamInfo {
                is_initiator: true,
                handshake_hash: hh,
                remote_public_key: None,
            },
        ),
        Mux::new(
            br,
            bw,
            StreamInfo {
                is_initiator: false,
                handshake_hash: hh,
                remote_public_key: None,
            },
        ),
    )
}

#[tokio::test(start_paused = true)]
async fn idle_cores_are_collected_unless_used_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let session = store.get(GetOptions::name("gone")).await.unwrap();
    drop(session);
    let kept = store.get(GetOptions::name("kept")).await.unwrap();
    let dk = *kept.discovery_key();
    drop(kept);
    assert_eq!(store.open_cores().len(), 2);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // The struck core is used again before its fourth strike: it is spared.
    let back = store
        .get(GetOptions {
            discovery_key: Some(dk),
            ..Default::default()
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let open: Vec<_> = store
        .open_cores()
        .iter()
        .map(|c| *c.discovery_key())
        .collect();
    assert_eq!(
        open,
        vec![dk],
        "the unused core was collected, the reused one kept"
    );
    drop(back);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(store.open_cores().is_empty());
}

#[tokio::test]
async fn a_peer_gets_any_stored_core_on_demand() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let keys: Vec<[u8; 32]> = {
        let writer = Corestore::open(da.path()).unwrap();
        let mut keys = vec![];
        for name in ["one", "two", "three"] {
            let core = writer.get(GetOptions::name(name)).await.unwrap();
            core.append(&[name.as_bytes()]).await.unwrap();
            keys.push(*core.key());
        }
        keys
    };
    // Reopened: nothing is open until the remote asks.
    let writer = Corestore::open(da.path()).unwrap();
    assert!(writer.open_cores().is_empty());
    let reader = Corestore::open(db.path()).unwrap();
    let (ma, mb) = link();
    writer.replicate(&ma);
    reader.replicate(&mb);
    for (key, name) in keys.iter().zip(["one", "two", "three"]) {
        let core = reader.get(GetOptions::key(*key)).await.unwrap();
        let block = timeout(Duration::from_secs(10), core.get(0, Get::default()))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&block[..], name.as_bytes());
    }
    assert_eq!(
        writer.open_cores().len(),
        3,
        "each core was opened on demand"
    );
}

#[tokio::test]
async fn a_stored_core_closed_here_still_serves_a_third_peer() {
    let (da, db, dc) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let a = Corestore::open(da.path()).unwrap();
    let b = Corestore::open(db.path()).unwrap();
    let key = {
        let c = Corestore::open(dc.path()).unwrap();
        let writer = c.get(GetOptions::name("writer")).await.unwrap();
        writer.append(&[b"hello".as_slice()]).await.unwrap();
        let key = *writer.key();
        // a fetches the block, then closes its session and the connection.
        let (ma, mc) = link();
        a.replicate(&ma);
        c.replicate(&mc);
        let fetched = a.get(GetOptions::key(key)).await.unwrap();
        let block = timeout(Duration::from_secs(10), fetched.get(0, Get::default()))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&block[..], b"hello");
        drop(fetched);
        ma.destroy();
        mc.destroy();
        c.close().await;
        key
    };
    assert!(
        a.open_cores()
            .iter()
            .any(|core| core.key() == &key && core.is_closed()),
        "a has the core stored but closed"
    );

    // b reaches a over a fresh connection and wants the same core.
    let (ma, mb) = link();
    a.replicate(&ma);
    b.replicate(&mb);
    let view = b.get(GetOptions::key(key)).await.unwrap();
    let block = timeout(Duration::from_secs(10), view.get(0, Get::default()))
        .await
        .expect("a stored core closed in this process must pair on demand")
        .unwrap()
        .unwrap();
    assert_eq!(&block[..], b"hello");
    let served = a.open_cores();
    assert!(
        served
            .iter()
            .any(|core| core.key() == &key && !core.is_idle()),
        "the reopened core stays open while b uses it"
    );
}

#[tokio::test]
async fn reopening_waits_for_the_previous_replication_actor_to_release_its_channels() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let writer = Corestore::open(da.path()).unwrap();
    let reader = Corestore::open(db.path()).unwrap();
    let source = writer.get(GetOptions::name("writer")).await.unwrap();
    source.append(&[b"first".as_slice()]).await.unwrap();
    let key = *source.key();
    let view = reader.get(GetOptions::key(key)).await.unwrap();
    let (ma, mb) = link();
    writer.replicate(&ma);
    reader.replicate(&mb);
    assert_eq!(
        timeout(Duration::from_secs(5), view.get(0, Get::default()))
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"first".as_slice()
    );
    let old = view.core().clone();
    assert_eq!(old.peer_count(), 1);
    drop(view);
    assert!(old.is_closed());

    // On this current-thread runtime, get must yield until the old actor has detached.
    let reopened = reader.get(GetOptions::key(key)).await.unwrap();
    assert!(!reopened.core().same_instance(&old));
    assert_eq!(old.peer_count(), 0, "replacement published before teardown");
    source.append(&[b"second".as_slice()]).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), reopened.get(1, Get::default()))
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"second".as_slice()
    );
    ma.destroy();
    mb.destroy();
    reader.close().await;
    writer.close().await;
}
