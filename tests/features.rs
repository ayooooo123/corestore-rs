use corestore::{Corestore, GetOptions};
use hypercore::{CoreError, GetOptions as CoreGetOptions};

#[tokio::test]
async fn inflight_range_updates_open_and_future_cores() {
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let first = store.get(GetOptions::name("first")).await.unwrap();
    store.set_inflight_range((6, 8));
    assert_eq!(first.inflight_range(), Some((6, 8)));
    let second = store.get(GetOptions::name("second")).await.unwrap();
    assert_eq!(second.inflight_range(), Some((6, 8)));
    let mut options = GetOptions::name("first");
    options.inflight_range = Some((16, 48));
    let cached = store.get(options).await.unwrap();
    assert_eq!(cached.inflight_range(), Some((16, 48)));
    store.set_inflight_range((8, 24));
    assert_eq!(first.inflight_range(), Some((8, 24)));
    assert_eq!(second.inflight_range(), Some((8, 24)));
}

#[tokio::test]
async fn close_reopens_alias_and_read_only_infos() {
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let mut opts = GetOptions::name("view");
    opts.manifest_version = Some(3);
    opts.inflight_range = Some((256, 512));
    let core = store.get(opts).await.unwrap();
    let key = *core.key();
    let dk = *core.discovery_key();
    core.append(&[b"hello"]).await.unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let other = Corestore::open(other_dir.path()).unwrap();
    let reader = other.get(GetOptions::key(key)).await.unwrap();
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
    store.close().await;
    assert!(matches!(
        core.get(0, CoreGetOptions::default()).await,
        Err(CoreError::Closed)
    ));
    let reopened = Corestore::open_read_only(dir.path()).unwrap();
    assert!(reopened.read_only());
    assert!(reopened.open_cores().is_empty());
    assert_eq!(reopened.storage_infos(&[dk]).unwrap()[0].unwrap().length, 1);
    assert!(reopened.open_cores().is_empty());
    let again = reopened.get(GetOptions::name("view")).await.unwrap();
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

#[tokio::test]
async fn scope_and_exclusive_lifecycle() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let store = Corestore::open(dir.path()).unwrap();
    let first_scope = store.session();
    let second_scope = store.session();
    let mut opts = GetOptions::name("shared");
    opts.exclusive = true;
    let first = first_scope.get(opts.clone()).await.unwrap();
    let mut inactive = GetOptions::name("shared");
    inactive.inactive = true;
    let second = second_scope.get(inactive).await.unwrap();
    assert!(!second.is_active());
    let mut pending = Box::pin(second_scope.get(opts.clone()));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pending)
            .await
            .is_err()
    );
    drop(pending);
    let lease = first.take_exclusive().unwrap();
    second.attach_exclusive(lease).unwrap();
    first_scope.close().await;
    assert!(first.is_closed());
    assert!(matches!(
        first.get(0, CoreGetOptions::default()).await,
        Err(CoreError::Closed)
    ));
    second.append(&[b"ok"]).await.unwrap();
    let mut pending = Box::pin(second_scope.get(opts));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pending)
            .await
            .is_err()
    );
    second.close();
    let acquired = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap();
    acquired.close();
    assert!(acquired.core().is_closed());
    let reopened = second_scope.get(GetOptions::name("shared")).await.unwrap();
    assert_eq!(
        reopened
            .get(0, CoreGetOptions::default())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"ok"
    );
    assert!(first_scope.get(GetOptions::name("shared")).await.is_err());
    store.close().await;
}
