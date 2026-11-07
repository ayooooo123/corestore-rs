use corestore::{Corestore, GetOptions};
use hypercore::{CoreError, GetOptions as CoreGetOptions};

#[tokio::test]
async fn close_reopens_alias_and_read_only_infos() {
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let mut opts = GetOptions::name("view");
    opts.manifest_version = Some(3);
    opts.inflight_range = Some((256, 512));
    let core = store.get(opts).unwrap();
    let key = *core.key();
    let dk = *core.discovery_key();
    core.append(&[b"hello"]).await.unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let other = Corestore::open(other_dir.path()).unwrap();
    let reader = other.get(GetOptions::key(key)).unwrap();
    let ((ar, aw), (br, bw)) = protomux::memory::duplex(64);
    let info = |initiator| protomux::StreamInfo {
        is_initiator: initiator,
        handshake_hash: Some([3; 64]),
        remote_public_key: None,
    };
    let a = protomux::Mux::new(ar, aw, info(true));
    let b = protomux::Mux::new(br, bw, info(false));
    store.replicate(&a);
    other.replicate(&b);
    let data = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.get(0, CoreGetOptions::default()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(data.as_ref(), b"hello");
    let infos = store.storage_infos(&[dk, [0; 32]]).unwrap();
    assert_eq!(infos[0].unwrap().length, 1);
    assert!(infos[1].is_none());
    store.close();
    assert!(matches!(
        core.get(0, CoreGetOptions::default()).await,
        Err(CoreError::Closed)
    ));
    let reopened = Corestore::open_read_only(dir.path()).unwrap();
    assert!(reopened.read_only());
    assert!(reopened.open_cores().is_empty());
    assert_eq!(reopened.storage_infos(&[dk]).unwrap()[0].unwrap().length, 1);
    assert!(reopened.open_cores().is_empty());
    let again = reopened.get(GetOptions::name("view")).unwrap();
    assert_eq!(*again.key(), key);
    assert_eq!(
        again
            .get(0, CoreGetOptions::default())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"hello"
    );
    assert!(again.append(&[b"x"]).await.is_err());
}
