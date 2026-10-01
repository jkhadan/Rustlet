//! Phase 3: images. Layers built in the test (or Alpine's minirootfs, from
//! `cargo xtask rootfs`'s cache) are imported into a store in a temp
//! directory, unpacked into snapshots as root, stacked with overlayfs, and
//! run with `rustlet-runc`. No registry: pulls are unit-tested against a fake
//! one in `rustlet-image`. Run with `cargo xtask itest -- im_`.

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

use rustlet_image::import::import;
use rustlet_image::runspec::{self, RunOptions};
use rustlet_image::snapshot::SnapshotEvent;
use rustlet_image::{Digest, Error, Image};
use rustlet_itests::images::{LayerBuilder, Mounted, TestStore, alpine_layer};
use rustlet_itests::*;
use rustlet_runtime::oci_spec::image::ConfigBuilder;
use rustlet_sys::xattr;

const ROOT: (u64, u64) = (0, 0);

fn meta(p: &Path) -> std::fs::Metadata {
    std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn owner_mode(p: &Path) -> (u32, u32, u32) {
    let m = meta(p);
    (m.uid(), m.gid(), m.permissions().mode() & 0o7777)
}

fn is_whiteout(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_char_device() && m.rdev() == 0)
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

/// Runs `options` on a mounted image and checks the host mount table.
fn run_image(image: &Image, mounted: &Mounted, options: RunOptions) -> Output {
    let spec = runspec::build(image, &mounted.root(), &options).unwrap();
    let bundle = TestBundle::new(&spec);
    let before = host_mounts();
    let out = bundle.command().output().unwrap();
    assert_host_mounts_unchanged(&before, &host_mounts());
    Output {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn sh(script: &str) -> RunOptions {
    RunOptions { args: vec!["sh".into(), "-c".into(), script.into()], ..Default::default() }
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_unpack_preserves_owners_modes_and_file_capabilities() {
    // VFS_CAP_REVISION_2 | EFFECTIVE, permitted = CAP_NET_RAW (bit 13): what
    // `setcap cap_net_raw+ep` writes.
    let cap: [u8; 20] = [0x01, 0, 0, 0x02, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let layer = LayerBuilder::new()
        .dir("srv/", 0o1777, ROOT)
        .dir("home/app/", 0o750, (1000, 1000))
        .file("home/app/notes", b"n", 0o640, (1000, 1001))
        .file("usr/bin/su-like", b"x", 0o4755, ROOT)
        .file_with_xattrs("usr/bin/ping-like", b"p", 0o755, ROOT, &[("security.capability", &cap)])
        .symlink("home/app/link", "notes", (1000, 1000))
        .device("dev/sda", tar::EntryType::Block, 8, 0)
        .finish();
    let s = TestStore::new();
    let image = s.import("local/owners:1", &[layer], &["true"], None);
    let fs = s.snapshots(&image)[0].fs();
    assert_eq!(owner_mode(&fs.join("srv")), (0, 0, 0o1777));
    assert_eq!(owner_mode(&fs.join("home/app")), (1000, 1000, 0o750));
    assert_eq!(owner_mode(&fs.join("home/app/notes")), (1000, 1001, 0o640));
    assert_eq!(owner_mode(&fs.join("usr/bin/su-like")), (0, 0, 0o4755), "setuid survives the chown");
    assert_eq!(xattr::lget(&fs.join("usr/bin/ping-like"), "security.capability").unwrap(), cap);
    let link = meta(&fs.join("home/app/link"));
    assert!(link.file_type().is_symlink());
    assert_eq!((link.uid(), link.gid()), (1000, 1000), "the symlink itself is chowned");
    assert!(!fs.join("dev/sda").exists(), "device nodes are skipped");
    assert_eq!(owner_mode(&fs.join("usr")), (0, 0, 0o755), "implicit parents: root, 0755");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_unpack_stays_inside_the_layer_as_root() {
    let s = TestStore::new();
    let layer = LayerBuilder::new()
        .dir("etc/", 0o755, ROOT)
        .symlink("hostetc", "/etc", ROOT)
        .symlink("up", "../../../../../../../../..", ROOT)
        .file("hostetc/rustlet-itest-escape", b"x", 0o644, ROOT)
        .file("up/tmp/rustlet-itest-escape-up", b"y", 0o644, ROOT)
        .finish();
    let image = s.import("local/inside:1", &[layer], &["true"], None);
    let fs = s.snapshots(&image)[0].fs();
    assert_eq!(std::fs::read_to_string(fs.join("etc/rustlet-itest-escape")).unwrap(), "x");
    assert_eq!(std::fs::read_to_string(fs.join("tmp/rustlet-itest-escape-up")).unwrap(), "y");
    assert!(!Path::new("/etc/rustlet-itest-escape").exists());
    assert!(!Path::new("/tmp/rustlet-itest-escape-up").exists());

    // A hard link may not reach the host's files, through a symlink or not.
    let passwd_links = meta(Path::new("/etc/passwd")).nlink();
    for layer in [
        LayerBuilder::new().symlink("hostetc", "/etc", ROOT).hardlink("pw", "hostetc/passwd").finish(),
        LayerBuilder::new().hardlink("pw", "../../../../../../etc/passwd").finish(),
        LayerBuilder::new().file("../../../../../../tmp/rustlet-itest-dotdot", b"z", 0o644, ROOT).finish(),
        // A symlink to a directory the layer doesn't have: refused, not
        // created on the host or in the layer.
        LayerBuilder::new().symlink("t", "/tmp", ROOT).file("t/rustlet-itest-dangling", b"z", 0o644, ROOT).finish(),
    ] {
        let image = s.import("local/outside:1", &[layer], &["true"], None);
        let e = s.store.snapshots().ensure(s.store.content(), &image, &mut |_| {}).unwrap_err();
        assert!(matches!(e, Error::Invalid(_)), "{e}");
        assert!(s.store.snapshots().get(&image.layers[0].chain_id).unwrap().is_none());
    }
    assert_eq!(meta(Path::new("/etc/passwd")).nlink(), passwd_links);
    assert!(!Path::new("/tmp/rustlet-itest-dotdot").exists());
    assert!(!Path::new("/tmp/rustlet-itest-dangling").exists());
    // Failed unpacks leave nothing behind, not even their `.tmp-*`.
    let left: Vec<_> = names(s.store.snapshots().dir()).into_iter().filter(|n| n.starts_with('.')).collect();
    assert!(left.is_empty(), "{left:?}");
}

/// L0: etc/{a,keep}, doc/{x,y}, gone/inner; L1 deletes etc/a and gone,
/// makes doc opaque with a z; L2 brings etc/a back.
fn whiteout_layers() -> [Vec<u8>; 3] {
    [
        LayerBuilder::new()
            .dir("etc/", 0o755, ROOT)
            .file("etc/a", b"a0", 0o644, ROOT)
            .file("etc/keep", b"k0", 0o644, ROOT)
            .file("doc/x", b"x", 0o644, ROOT)
            .file("doc/y", b"y", 0o644, ROOT)
            .file("gone/inner", b"i", 0o644, ROOT)
            .finish(),
        LayerBuilder::new().whiteout("etc/a").opaque("doc").file("doc/z", b"z1", 0o644, ROOT).whiteout("gone").finish(),
        LayerBuilder::new().file("etc/a", b"a2", 0o644, ROOT).finish(),
    ]
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_overlay_applies_whiteouts_and_opaque_directories() {
    let s = TestStore::new();
    let [l0, l1, l2] = whiteout_layers();
    let two = s.import("local/wh:2", &[l0.clone(), l1.clone()], &["true"], None);
    let three = s.import("local/wh:3", &[l0, l1, l2], &["true"], None);

    let snaps = s.snapshots(&three);
    assert!(is_whiteout(&snaps[1].fs().join("etc/a")));
    assert!(is_whiteout(&snaps[1].fs().join("gone")));
    assert_eq!(xattr::lget(&snaps[1].fs().join("doc"), "trusted.overlay.opaque").unwrap(), b"y");

    let m = s.mount(&two, false);
    assert!(!m.path("etc/a").exists(), "whited out");
    assert_eq!(std::fs::read_to_string(m.path("etc/keep")).unwrap(), "k0");
    assert_eq!(names(&m.path("doc")), ["z"], "opaque: x and y are hidden");
    assert!(!m.path("gone").exists());
    assert_eq!(names(&m.root()), ["doc", "etc"]);

    let m = s.mount(&three, false);
    assert_eq!(std::fs::read_to_string(m.path("etc/a")).unwrap(), "a2", "a higher layer brings it back");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_container_writes_go_to_the_upper_layer() {
    let s = TestStore::new();
    let [l0, l1, _] = whiteout_layers();
    let image = s.import("local/cow:1", &[l0, l1], &["true"], None);
    let snaps = s.snapshots(&image);
    let before = host_mounts();
    let m = s.mount(&image, false);
    let added: Vec<_> = host_mounts().into_iter().filter(|x| !before.contains(x)).collect();
    assert_eq!(added.len(), 1, "exactly the overlay: {added:?}");
    assert_eq!(added[0].1, "overlay");

    // Modify a lower file: copied up, the snapshot untouched.
    std::fs::write(m.path("etc/keep"), "k-new").unwrap();
    assert_eq!(std::fs::read_to_string(m.upper("etc/keep")).unwrap(), "k-new");
    assert_eq!(std::fs::read_to_string(snaps[0].fs().join("etc/keep")).unwrap(), "k0");
    // Delete a lower file: a whiteout in upper.
    std::fs::remove_file(m.path("doc/z")).unwrap();
    assert!(is_whiteout(&m.upper("doc/z")));
    assert!(snaps[1].fs().join("doc/z").exists());
    // Recreate a deleted directory: opaque in upper.
    std::fs::remove_dir_all(m.path("etc")).unwrap();
    std::fs::create_dir(m.path("etc")).unwrap();
    assert_eq!(xattr::lget(&m.upper("etc"), "trusted.overlay.opaque").unwrap(), b"y");
    assert!(names(&m.path("etc")).is_empty());
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_digest_mismatches_leave_no_snapshot() {
    let s = TestStore::new();
    let layer = LayerBuilder::new().file("f", b"data", 0o644, ROOT).finish();
    let image = s.import("local/digest:1", &[layer], &["true"], None);
    let content = s.store.content();

    // A config whose diff ID doesn't match the layer: same blob, new
    // config, new manifest.
    let mut config: serde_json::Value =
        serde_json::from_slice(&content.read_blob(&image.config_digest, 1 << 20).unwrap()).unwrap();
    config["rootfs"]["diff_ids"][0] = serde_json::Value::String(Digest::of(b"something else").to_string());
    let config = serde_json::to_vec(&config).unwrap();
    let config_digest = content.write_blob(&config).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&content.read_blob(&image.manifest_digest, 1 << 20).unwrap()).unwrap();
    manifest["config"]["digest"] = serde_json::Value::String(config_digest.to_string());
    manifest["config"]["size"] = serde_json::Value::from(config.len());
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let manifest_digest = content.write_blob(&manifest).unwrap();
    let bad = Image::from_manifest(content, &manifest_digest, None, None).unwrap();
    let e = s.store.snapshots().ensure(content, &bad, &mut |_| {}).unwrap_err();
    assert!(matches!(&e, Error::DigestMismatch { what, .. } if what.contains("diff ID")), "{e}");

    // A blob replaced on disk after it was verified, by one that still
    // decompresses to the very same tar (gzip isn't canonical): the diff ID
    // matches, and only the blob digest can tell.
    let blob = content.blob_path(&image.layers[0].blob);
    let original = std::fs::read(&blob).unwrap();
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(&original[..]).read_to_end(&mut tar).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    gz.write_all(&tar).unwrap();
    let recompressed = gz.finish().unwrap();
    assert_ne!(recompressed, original);
    std::fs::write(&blob, &recompressed).unwrap();
    let e = s.store.snapshots().ensure(content, &image, &mut |_| {}).unwrap_err();
    assert!(matches!(&e, Error::DigestMismatch { what, .. } if what.contains("blob digest")), "{e}");

    // One that no longer decompresses (the deflate stream's last byte, just
    // before gzip's 8-byte trailer): refused while reading it.
    let mut corrupt = original;
    let n = corrupt.len();
    corrupt[n - 9] ^= 0xff;
    std::fs::write(&blob, &corrupt).unwrap();
    let e = s.store.snapshots().ensure(content, &image, &mut |_| {}).unwrap_err();
    assert!(matches!(e, Error::DigestMismatch { .. } | Error::Io { .. }), "{e}");

    assert!(names(s.store.snapshots().dir()).is_empty(), "{:?}", names(s.store.snapshots().dir()));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_layers_are_shared_between_images() {
    let s = TestStore::new();
    let base = LayerBuilder::new().file("base", b"b", 0o644, ROOT).finish();
    let a = s.import(
        "local/a:1",
        &[base.clone(), LayerBuilder::new().file("a", b"a", 0o644, ROOT).finish()],
        &["true"],
        None,
    );
    let b = s.import("local/b:1", &[base, LayerBuilder::new().file("b", b"b", 0o644, ROOT).finish()], &["true"], None);
    s.snapshots(&a);
    let mut events = Vec::new();
    s.store
        .snapshots()
        .ensure(s.store.content(), &b, &mut |e| {
            events.push(match e {
                SnapshotEvent::Exists { .. } => "exists",
                SnapshotEvent::Unpacking { .. } => "unpacking",
                SnapshotEvent::Unpacked { .. } => "unpacked",
            })
        })
        .unwrap();
    assert_eq!(events, ["exists", "unpacking", "unpacked"]);
    assert_eq!(s.store.snapshots().list().unwrap().len(), 3);
    assert_eq!(a.layers[0].chain_id, b.layers[0].chain_id);
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_concurrent_unpacks_of_the_same_image_agree() {
    let s = TestStore::new();
    let layers: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let mut b = LayerBuilder::new();
            for j in 0..200 {
                b = b.file(&format!("l{i}/f{j}"), format!("{i}-{j}").as_bytes(), 0o644, ROOT);
            }
            b.finish()
        })
        .collect();
    let image = s.import("local/race:1", &layers, &["true"], None);
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| s.store.snapshots().ensure(s.store.content(), &image, &mut |_| {}).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &results {
        assert_eq!(r, &results[0]);
    }
    assert_eq!(names(s.store.snapshots().dir()).len(), 3, "{:?}", names(s.store.snapshots().dir()));
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_run_an_imported_alpine_image() {
    let s = TestStore::new();
    let top = LayerBuilder::new().file("etc/motd", b"hello from a layer\n", 0o644, ROOT).whiteout("etc/issue").finish();
    let image = s.import("local/alpine-plus:1", &[alpine_layer(), top], &["/bin/sh"], None);
    let m = s.mount(&image, false);
    let out = run_image(
        &image,
        &m,
        sh("cat /etc/motd; test -e /etc/issue || echo issue-gone; echo $PATH; pwd; id -u; echo written > /tmp/w"),
    );
    assert_eq!(
        out.ok(),
        "hello from a layer\nissue-gone\n/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n/\n0\n",
        "{out:#?}"
    );
    assert_eq!(std::fs::read_to_string(m.upper("tmp/w")).unwrap(), "written\n", "writes land in the upper layer");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_user_and_workdir_come_from_the_image() {
    let s = TestStore::new();
    let top = LayerBuilder::new()
        .file("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:App:/home/app:/bin/sh\n", 0o644, ROOT)
        .file("etc/group", b"root:x:0:root\napp:x:1000:\nextra:x:2000:app\n", 0o644, ROOT)
        .dir("home/app/", 0o750, (1000, 1000))
        .finish();
    let config = ConfigBuilder::default()
        .user("app".to_string())
        .working_dir("/home/app".to_string())
        .env(vec!["PATH=/usr/bin:/bin".to_string()])
        .cmd(vec![
            "sh".to_string(),
            "-c".to_string(),
            "id; pwd; echo $HOME; touch mine; stat -c %u:%g mine".to_string(),
        ])
        .build()
        .unwrap();
    let image = import(s.store.content(), "local/user:1", &[alpine_layer(), top], config).unwrap();
    let m = s.mount(&image, false);
    let out = run_image(&image, &m, RunOptions::default());
    assert_eq!(
        out.ok(),
        "uid=1000(app) gid=1000(app) groups=1000(app),2000(extra)\n/home/app\n/home/app\n1000:1000\n",
        "{out:#?}"
    );
    // `-u` overrides the image's user.
    let out = run_image(&image, &m, RunOptions { user: Some("0:2000".into()), ..sh("id -u; id -g; id -G") });
    assert_eq!(out.ok(), "0\n2000\n2000\n", "{out:#?}");
}

#[test]
#[ignore = "needs root: run with `cargo xtask itest`"]
fn im_userns_idmapped_layers_show_container_root() {
    let s = TestStore::new();
    let top = LayerBuilder::new().file("etc/motd", b"m\n", 0o644, ROOT).finish();
    let image = s.import("local/alpine-userns:1", &[alpine_layer(), top], &["/bin/sh"], None);
    let snaps = s.snapshots(&image);
    let before = host_mounts();
    let m = s.mount(&image, true);
    let added: Vec<_> = host_mounts().into_iter().filter(|x| !before.contains(x)).collect();
    assert_eq!(added.len(), 1, "only the overlay stays mounted; the staged idmapped layers are gone: {added:?}");

    // On disk the image's files still belong to uid 0; through the idmapped
    // layers the host sees container root's host id.
    assert_eq!(meta(&snaps[0].fs().join("bin/busybox")).uid(), 0);
    assert_eq!(meta(&m.path("bin/busybox")).uid(), 1_000_000);
    assert_eq!((meta(&m.root()).uid(), meta(&m.root()).gid()), (1_000_000, 1_000_000), "upper's root");

    let options = RunOptions {
        userns_remap: true,
        ..sh("stat -c %u:%g /bin/busybox /etc/shadow; id -u; cat /proc/self/uid_map; \
              touch /made-inside; stat -c %u /made-inside; chown 5:5 /etc/motd")
    };
    let out = run_image(&image, &m, options);
    let lines: Vec<&str> = out.ok().lines().map(str::trim).collect();
    assert_eq!(lines, ["0:0", "0:42", "0", "0    1000000      65536", "0"], "{out:#?}");
    // What container root wrote is host 1000000's; a copied-up file keeps
    // its (mapped) owner, here changed to container 5 = host 1000005.
    assert_eq!(meta(&m.upper("made-inside")).uid(), 1_000_000);
    assert_eq!((meta(&m.upper("etc/motd")).uid(), meta(&m.upper("etc/motd")).gid()), (1_000_005, 1_000_005));
    assert_eq!(meta(&snaps[1].fs().join("etc/motd")).uid(), 0, "the snapshot itself is untouched");
}
