//! QFLTL-encrypted, mutually authenticated transport for ductei-sync.
//!
//! Wraps a TCP connection with QFLTL's post-quantum session crypto
//! (ML-KEM-768 + HKDF-SHA256 + AES-256-GCM, see the standalone
//! `qfltl-crypto` crate) underneath DUCTEI's existing length-prefixed JSON
//! framing (`ductei_core::transport`). It sits on top of, not instead of,
//! Tailscale/WireGuard and the `--allow-ip` list.
//!
//! # Identity and pinning
//! Each node has a persistent ML-KEM-768 keypair, stored as a 64-byte seed in
//! `<state>/qfltl/identity.seed.dpapi` on Windows (DPAPI-wrapped) or
//! `<state>/qfltl/identity.seed` (mode 0600) elsewhere, generated on first
//! use. Its public key is published at `<state>/qfltl/identity.pub`.
//! Peers' public keys are pinned by ROLE, copied out of band and checked by
//! fingerprint, like SSH known_hosts:
//! - `<state>/qfltl/known_servers/<peer>.pub`: servers this node pushes to,
//!   looked up by the exact `--peer` string it dials;
//! - `<state>/qfltl/known_clients/<label>.pub`: clients this node's serve
//!   accepts.
//! A key pinned as a server is never accepted as a client, and the reverse.
//! The pre-split `known_peers/` directory is ignored (the CLI warns).
//! Re-pinning a name to a different key needs an explicit `replace`.
//!
//! # Handshake v3 (one per TCP connection)
//! ```text
//! C -> S: [u32 len]["QFLTLv3\0"][client fp, 32B][ct1 = Encaps(server_pk)][ek_e]
//! S -> C: [u32 len][ct2 = Encaps(client_pk)][ct3 = Encaps(ek_e)]
//! keys  = HKDF(salt = SHA256(label|magic|fp_c|fp_s|ct1|ek_e|ct2|ct3),
//!              ikm = ss1|ss2|ss3)  -> one key per direction (c2s, s2c)
//! client wipes dk_e as soon as it has decapsulated ct3
//! S -> C: record "qfltl-ok-s"   (server proves it holds the pinned key)
//! C -> S: record "qfltl-ok-c"   (client proves it holds its private key)
//! ```
//! Only the real server can recover ss1 and only the real client can recover
//! ss2, which authenticates both ends. ss3 comes from a fresh ML-KEM keypair
//! (`ek_e`/`dk_e`) the client makes for this one connection and wipes right
//! after use (ml-kem's `zeroize` feature is on in qfltl-crypto), so
//! recorded traffic stays sealed even if BOTH long-term identity keys leak
//! later: forward secrecy. The client sends nothing but the hello until the server has proven
//! itself, and the server hands the connection to `serve_stream` (and relaxes
//! its handshake timeout) only after the client has proven itself, so an
//! unauthenticated connection can hold the one-at-a-time server for at most
//! [`HANDSHAKE_TIMEOUT`]. An unpinned client fingerprint runs the same
//! exchange against a throwaway key, so from outside it is indistinguishable
//! from a wrong key (no pin oracle).
//!
//! After the handshake every byte in both directions is an AEAD record:
//! ```text
//! [u32 LE length][AES-256-GCM ciphertext + 16-byte tag]
//! ```
//! The nonce is a per-direction sequence number that both ends count and
//! never sends, so replayed, reordered, dropped or reflected records fail to
//! open. The JSON envelope format inside is unchanged, so Qallow byte-compat
//! is unaffected. v3 does not interoperate with v2: upgrade both ends.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use qfltl_crypto::{encapsulate, fingerprint, KemKeypair, Role, SecureChannel, PUBLIC_KEY_LEN};

const HS_MAGIC: &[u8; 8] = b"QFLTLv3\0";
const CONFIRM_SERVER: &[u8] = b"qfltl-ok-s";
const CONFIRM_CLIENT: &[u8] = b"qfltl-ok-c";
/// ML-KEM-768 ciphertext length; a hello of any other size is refused.
const ML_KEM_768_CT_LEN: usize = 1088;
/// A connected peer that does not finish the whole handshake (including the
/// client's proof) in this long is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// After the handshake, a connection that goes silent this long is dropped,
/// so even an authenticated peer can't stall the one-at-a-time server.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

fn qfltl_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("qfltl")
}

/// Which pin store a key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinRole {
    /// A server this node pushes to (pinned under the exact `--peer` string).
    Server,
    /// A client this node's serve accepts (pinned under any label).
    Client,
}

impl PinRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "server" => Some(Self::Server),
            "client" => Some(Self::Client),
            _ => None,
        }
    }

    fn dir(self, state_dir: &Path) -> PathBuf {
        match self {
            Self::Server => known_servers_dir(state_dir),
            Self::Client => known_clients_dir(state_dir),
        }
    }
}

/// Pinned keys of servers this node pushes to.
pub fn known_servers_dir(state_dir: impl AsRef<Path>) -> PathBuf {
    qfltl_dir(state_dir.as_ref()).join("known_servers")
}

/// Pinned keys of clients this node's serve accepts.
pub fn known_clients_dir(state_dir: impl AsRef<Path>) -> PathBuf {
    qfltl_dir(state_dir.as_ref()).join("known_clients")
}

/// True if the pre-split `known_peers/` store still holds pins. They are
/// ignored; the operator must re-pin each one under its role.
pub fn legacy_pins_present(state_dir: impl AsRef<Path>) -> bool {
    fs::read_dir(qfltl_dir(state_dir.as_ref()).join("known_peers"))
        .map(|d| d.flatten().any(|e| e.path().extension().is_some_and(|x| x == "pub")))
        .unwrap_or(false)
}

/// Private identity seed at rest. On Windows it is DPAPI-wrapped in user
/// scope (`identity.seed.dpapi`): only this Windows user on this machine can
/// unwrap it, so a copied state folder leaks nothing. That is a defence
/// against the file being copied, not against code running as this user.
/// Same pattern as ductei-mcp's signing-key store.
#[cfg(windows)]
mod keystore {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub const AVAILABLE: bool = true;

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe {
            LocalFree(out.pbData as _);
        }
        v
    }

    pub fn wrap(secret: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: secret.len() as u32, pbData: secret.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let desc: Vec<u16> = "ductei-sync qfltl identity\0".encode_utf16().collect();
        let ok = unsafe {
            CryptProtectData(&input, desc.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err("CryptProtectData failed".into());
        }
        Ok(take(out))
    }

    pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: wrapped.len() as u32, pbData: wrapped.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        };
        if ok == 0 {
            return Err("CryptUnprotectData failed (seed wrapped by another user or machine?)".into());
        }
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod keystore {
    pub const AVAILABLE: bool = false;
    pub fn wrap(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI key store is Windows-only".into())
    }
    pub fn unwrap(_: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI key store is Windows-only".into())
    }
}

fn keystore_err(e: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

fn tmp_sibling(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!("{name}.{}.{n}.tmp", std::process::id()))
}

/// Open a brand-new file, owner-only (0600) on Unix from the first byte.
fn open_new_private(path: &Path) -> io::Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Create `path` with `bytes` only if it does not exist yet, so two
/// processes racing to create it can't both win. The content is written in
/// full to a private temp file and then hard-linked into place, so a
/// concurrent reader never sees a half-written file. Returns
/// `AlreadyExists` if someone else created it first.
fn write_new_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    {
        let mut f = open_new_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(e),
        Err(_) => {
            // No hard links on this filesystem: still create-if-absent.
            let mut f = open_new_private(path)?;
            f.write_all(bytes)?;
            f.sync_all()
        }
    }
}

/// Replace `path` atomically (write a temp file, then rename over).
fn write_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = tmp_sibling(path);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

fn bad_seed(e: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Read an existing identity, migrating a legacy plaintext seed to the
/// DPAPI-wrapped file on Windows. `Ok(None)` means there is none yet.
fn read_identity(dir: &Path) -> io::Result<Option<KemKeypair>> {
    use zeroize::Zeroizing;

    let plain = dir.join("identity.seed");
    let wrapped = dir.join("identity.seed.dpapi");
    match fs::read(&wrapped) {
        Ok(w) => {
            let seed = Zeroizing::new(keystore::unwrap(&w).map_err(keystore_err)?);
            return KemKeypair::from_seed_bytes(&seed).map(Some).map_err(bad_seed);
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    match fs::read(&plain) {
        Ok(p) => {
            let seed = Zeroizing::new(p);
            let kp = KemKeypair::from_seed_bytes(&seed).map_err(bad_seed)?;
            if keystore::AVAILABLE {
                match write_new_atomic(&wrapped, &keystore::wrap(&seed).map_err(keystore_err)?) {
                    Ok(()) => {}
                    // another process migrated it first: same seed, fine
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                match fs::remove_file(&plain) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(Some(kp))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Load this node's persistent QFLTL identity, generating one (and
/// publishing its public key) the first time this state dir is used.
/// Creation is create-if-absent, so `serve` and `push` starting together on
/// a fresh state dir end up with ONE identity, not two that overwrite each
/// other. A legacy plaintext `identity.seed` is migrated to the
/// DPAPI-wrapped file and removed on Windows.
pub fn load_or_generate_identity(state_dir: impl AsRef<Path>) -> io::Result<KemKeypair> {
    use zeroize::Zeroizing;

    let dir = qfltl_dir(state_dir.as_ref());
    fs::create_dir_all(&dir)?;
    let kp = match read_identity(&dir)? {
        Some(kp) => kp,
        None => {
            let fresh = KemKeypair::generate();
            let seed = Zeroizing::new(fresh.seed_bytes());
            let (target, bytes) = if keystore::AVAILABLE {
                (dir.join("identity.seed.dpapi"), Zeroizing::new(keystore::wrap(&seed).map_err(keystore_err)?))
            } else {
                (dir.join("identity.seed"), Zeroizing::new(seed.to_vec()))
            };
            match write_new_atomic(&target, &bytes) {
                Ok(()) => fresh,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => read_identity(&dir)?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "identity vanished during creation"))?,
                Err(e) => return Err(e),
            }
        }
    };
    publish_public_key(&state_dir, &kp)?;
    Ok(kp)
}

/// Path to this node's own public key, for handing to peers.
pub fn public_key_path(state_dir: impl AsRef<Path>) -> PathBuf {
    qfltl_dir(state_dir.as_ref()).join("identity.pub")
}

/// Write this node's public key out so it can be handed to peers.
pub fn publish_public_key(state_dir: impl AsRef<Path>, kp: &KemKeypair) -> io::Result<()> {
    fs::create_dir_all(qfltl_dir(state_dir.as_ref()))?;
    let path = public_key_path(&state_dir);
    let public = kp.public_bytes();
    if fs::read(&path).is_ok_and(|cur| cur == public) {
        return Ok(());
    }
    write_replace(&path, &public)
}

/// Lowercase hex of a key fingerprint, for humans to compare across machines.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pin a peer's public key under `name` in the `role` store (for a server
/// you dial, `name` must be the exact `--peer` string). Rejects anything
/// that isn't an ML-KEM-768 public key. Re-pinning the same key is a no-op;
/// pinning a DIFFERENT key over an existing pin is refused unless `replace`
/// is set, so a swapped key file can't silently take over a name. Returns
/// the new key's fingerprint.
pub fn pin_key(
    state_dir: impl AsRef<Path>,
    role: PinRole,
    name: &str,
    public: &[u8],
    replace: bool,
) -> io::Result<[u8; 32]> {
    if public.len() != PUBLIC_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not a QFLTL public key ({} bytes, expected {PUBLIC_KEY_LEN})", public.len()),
        ));
    }
    let fp = fingerprint(public);
    let dir = role.dir(state_dir.as_ref());
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.pub", sanitize(name)));
    match fs::read(&path) {
        Ok(old) if old == public => return Ok(fp),
        Ok(old) if !replace => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{name} is already pinned to a different key (pinned {}, new {}); pass --replace only if that machine's key was rotated on purpose",
                    fingerprint_hex(&fingerprint(&old)),
                    fingerprint_hex(&fp)
                ),
            ))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_replace(&path, public)?;
    Ok(fp)
}

/// Look up a server's pinned public key by the exact `--peer` string.
/// `Ok(None)` means not pinned; callers must refuse the connection.
pub fn pinned_server_key(state_dir: impl AsRef<Path>, peer: &str) -> io::Result<Option<Vec<u8>>> {
    let path = known_servers_dir(state_dir).join(format!("{}.pub", sanitize(peer)));
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Every well-formed pinned CLIENT key, for serve to match a client against.
/// Keys pinned as servers are deliberately not included.
pub fn load_pinned_clients(state_dir: impl AsRef<Path>) -> io::Result<Vec<Vec<u8>>> {
    let dir = known_clients_dir(state_dir);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut keys = vec![];
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|x| x == "pub") {
            let bytes = fs::read(&path)?;
            if bytes.len() == PUBLIC_KEY_LEN {
                keys.push(bytes);
            }
        }
    }
    Ok(keys)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

fn write_raw_frame(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)
}

fn read_raw_frame(r: &mut impl Read, max_len: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let n = u32::from_le_bytes(len_buf) as usize;
    if n > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handshake/record frame exceeds max length",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn invalid(e: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn denied(e: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, e)
}

/// Size of the client hello: magic, fingerprint, ct1, ephemeral public key.
const HELLO_LEN: usize = 8 + 32 + ML_KEM_768_CT_LEN + PUBLIC_KEY_LEN;
/// Size of the server reply: ct2 then ct3.
const REPLY_LEN: usize = 2 * ML_KEM_768_CT_LEN;

fn transcript(fp_c: &[u8], fp_s: &[u8], ct1: &[u8], ek_e: &[u8], ct2: &[u8], ct3: &[u8]) -> Vec<u8> {
    [HS_MAGIC.as_slice(), fp_c, fp_s, ct1, ek_e, ct2, ct3].concat()
}

fn send_record(w: &mut impl Write, ch: &mut SecureChannel, data: &[u8]) -> io::Result<()> {
    let rec = ch.seal(data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    write_raw_frame(w, &rec)?;
    w.flush()
}

fn recv_record(r: &mut impl Read, ch: &mut SecureChannel, max_len: usize) -> io::Result<Vec<u8>> {
    let rec = read_raw_frame(r, max_len)?;
    ch.open(&rec).map_err(invalid)
}

/// Client side: mutually authenticated handshake against the server's pinned
/// public key, using this node's own `identity`. Returns only after the
/// server has proven it holds the pinned key and this side has sent its own
/// proof, so nothing but the hello is ever sent to an impostor.
pub fn client_handshake<S: Read + Write>(
    stream: S,
    identity: &KemKeypair,
    pinned_server_public: &[u8],
) -> io::Result<EncryptedStream<S>> {
    client_handshake_as(stream, identity, identity.fingerprint(), pinned_server_public)
}

/// `claimed_fp` is split out only so tests can play an impostor that claims
/// a pinned client's fingerprint without holding its private key.
fn client_handshake_as<S: Read + Write>(
    mut stream: S,
    identity: &KemKeypair,
    claimed_fp: [u8; 32],
    pinned_server_public: &[u8],
) -> io::Result<EncryptedStream<S>> {
    let fp_s = fingerprint(pinned_server_public);
    let (ct1, ss1) = encapsulate(pinned_server_public).map_err(invalid)?;
    // Fresh per-connection keypair: the forward-secrecy half of the key.
    let ephemeral = KemKeypair::generate();
    let ek_e = ephemeral.public_bytes();
    let hello = [HS_MAGIC.as_slice(), &claimed_fp, &ct1, &ek_e].concat();
    write_raw_frame(&mut stream, &hello)?;
    stream.flush()?;

    let reply = read_raw_frame(&mut stream, 8192)?;
    if reply.len() != REPLY_LEN {
        return Err(invalid("not a QFLTL v3 handshake reply"));
    }
    let (ct2, ct3) = reply.split_at(ML_KEM_768_CT_LEN);
    let ss2 = identity.decapsulate(ct2).map_err(invalid)?;
    let ss3 = ephemeral.decapsulate(ct3).map_err(invalid)?;
    drop(ephemeral); // dk_e is wiped here; nothing can recover ss3 later
    let mut ch = SecureChannel::from_handshake(
        Role::Client,
        &[&ss1[..], &ss2[..], &ss3[..]],
        &transcript(&claimed_fp, &fp_s, &ct1, &ek_e, ct2, ct3),
    )
    .map_err(invalid)?;

    let confirm = recv_record(&mut stream, &mut ch, 64).map_err(|_| {
        denied("server failed QFLTL key confirmation (wrong server pin, this client not pinned there, or impostor)")
    })?;
    if confirm != CONFIRM_SERVER {
        return Err(denied("bad QFLTL key confirmation"));
    }
    send_record(&mut stream, &mut ch, CONFIRM_CLIENT)?;
    Ok(EncryptedStream::new(stream, ch))
}

/// Server side: accept a handshake only from a client whose key fingerprint
/// matches one of `pinned_clients` AND that proves it holds the matching
/// private key, using this node's own `identity`. The caller must have set
/// a read timeout (see [`HANDSHAKE_TIMEOUT`]) on the socket.
pub fn server_handshake<S: Read + Write>(
    mut stream: S,
    identity: &KemKeypair,
    pinned_clients: &[Vec<u8>],
) -> io::Result<EncryptedStream<S>> {
    // Exact size: magic + fingerprint + ct1 + ephemeral public key.
    let hello = read_raw_frame(&mut stream, 8192)?;
    if hello.len() != HELLO_LEN || &hello[..8] != HS_MAGIC {
        return Err(invalid("not a QFLTL v3 handshake"));
    }
    let fp_c: [u8; 32] = hello[8..40].try_into().expect("32 bytes");
    let ct1 = &hello[40..40 + ML_KEM_768_CT_LEN];
    let ek_e = &hello[40 + ML_KEM_768_CT_LEN..];

    // An unpinned fingerprint runs the same exchange against a throwaway
    // key, so from outside it looks exactly like a wrong key (no pin oracle).
    let decoy;
    let (client_pub, pinned): (&[u8], bool) =
        match pinned_clients.iter().find(|k| fingerprint(k) == fp_c) {
            Some(k) => (k.as_slice(), true),
            None => {
                decoy = KemKeypair::generate().public_bytes();
                (decoy.as_slice(), false)
            }
        };

    let outcome = server_exchange(&mut stream, identity, &fp_c, ct1, ek_e, client_pub);
    match (pinned, outcome) {
        (false, _) => Err(denied("client QFLTL key is not pinned")),
        (true, Ok(ch)) => Ok(EncryptedStream::new(stream, ch)),
        (true, Err(e)) => Err(e),
    }
}

fn server_exchange<S: Read + Write>(
    stream: &mut S,
    identity: &KemKeypair,
    fp_c: &[u8; 32],
    ct1: &[u8],
    ek_e: &[u8],
    client_pub: &[u8],
) -> io::Result<SecureChannel> {
    let ss1 = identity.decapsulate(ct1).map_err(invalid)?;
    let (ct2, ss2) = encapsulate(client_pub).map_err(invalid)?;
    // Rejects a malformed ephemeral key (ML-KEM encapsulation-key check).
    let (ct3, ss3) = encapsulate(ek_e).map_err(invalid)?;
    write_raw_frame(stream, &[ct2.as_slice(), &ct3].concat())?;

    let fp_s = identity.fingerprint();
    let mut ch = SecureChannel::from_handshake(
        Role::Server,
        &[&ss1[..], &ss2[..], &ss3[..]],
        &transcript(fp_c, &fp_s, ct1, ek_e, &ct2, &ct3),
    )
    .map_err(invalid)?;
    send_record(stream, &mut ch, CONFIRM_SERVER)?;

    // The client must prove it holds its private key before this connection
    // reaches serve_stream or gets a longer timeout.
    let proof = recv_record(stream, &mut ch, 64).map_err(|_| {
        denied("client failed QFLTL key confirmation (impostor, wrong key, or silent past the handshake timeout)")
    })?;
    if proof != CONFIRM_CLIENT {
        return Err(denied("bad QFLTL client confirmation"));
    }
    Ok(ch)
}

/// Bound on a single record on the wire. DUCTEI envelopes are small
/// (corrections, telemetry); 16 MiB is generous headroom.
const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;
/// Largest plaintext per record (the GCM tag adds 16 bytes), so a big
/// `write_all` is split into records the peer will accept.
const MAX_WRITE: usize = MAX_RECORD_LEN - 16;

/// A `Read + Write` adapter that seals every write and opens every read with
/// an established [`SecureChannel`]. Each `write()` becomes one AEAD record
/// (at most [`MAX_WRITE`] bytes); `read()` serves bytes from the last opened
/// record and pulls a new one when it runs dry, which preserves
/// `ductei_core::transport`'s `write_all`/`read_exact` framing without it
/// knowing encryption happens.
pub struct EncryptedStream<S> {
    inner: S,
    channel: SecureChannel,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> EncryptedStream<S> {
    fn new(inner: S, channel: SecureChannel) -> Self {
        Self {
            inner,
            channel,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// The underlying stream, e.g. to adjust socket timeouts.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: Write> Write for EncryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(MAX_WRITE);
        let rec = self
            .channel
            .seal(&buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        write_raw_frame(&mut self.inner, &rec)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Read> Read for EncryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Loop so an (authenticated) empty record is skipped instead of
        // looking like EOF to the caller.
        while self.read_pos >= self.read_buf.len() {
            let record = read_raw_frame(&mut self.inner, MAX_RECORD_LEN)?;
            self.read_buf = self.channel.open(&record).map_err(invalid)?;
            self.read_pos = 0;
        }
        let available = &self.read_buf[self.read_pos..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos += n;
        Ok(n)
    }
}

/// QFLTL-encrypted push: like [`crate::push_once`], but connects through a
/// mutually authenticated handshake and sends every envelope over the
/// resulting [`EncryptedStream`]. The envelope loop itself is the shared
/// [`crate::push_with_client`], so this is a different connection, not a
/// second implementation of the protocol.
///
/// Refuses to connect at all (`interrupted`, nothing sent) if `peer` has no
/// pinned server key, and stops before sending anything if the server fails
/// key confirmation.
pub fn push_once_qfltl(state: &crate::StateDir, peer: &str) -> io::Result<crate::PushReport> {
    use std::net::ToSocketAddrs;

    let interrupted = || crate::PushReport {
        interrupted: true,
        ..Default::default()
    };
    if !crate::has_pending(state, peer)? {
        return Ok(crate::PushReport::default());
    }
    let pin = match pinned_server_key(state.root(), peer)? {
        Some(k) => k,
        None => return Ok(interrupted()),
    };
    let identity = load_or_generate_identity(state.root())?;
    let addr = match peer.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(a) => a,
        None => return Ok(interrupted()),
    };
    let tcp = match std::net::TcpStream::connect_timeout(&addr, crate::CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(_) => return Ok(interrupted()),
    };
    let _ = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let encrypted = match client_handshake(tcp, &identity, &pin) {
        Ok(e) => e,
        Err(_) => return Ok(interrupted()),
    };
    let _ = encrypted.get_ref().set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = encrypted.get_ref().set_write_timeout(Some(IDLE_TIMEOUT));
    let client =
        ductei_core::transport::TcpClient::from_stream(encrypted).with_outbox_path(state.outbox());
    crate::push_with_client(state, peer, client)
}

/// QFLTL-encrypted serve: like [`crate::serve`], but each accepted
/// connection must complete a mutually authenticated handshake (client key
/// pinned under `<state>/qfltl/known_clients/`, re-read per connection so a
/// new pin needs no restart, plus the client's proof of its private key)
/// within [`HANDSHAKE_TIMEOUT`], and is then served through an
/// [`EncryptedStream`] by the same `ductei_core::transport::serve_stream`
/// plain serve uses, with [`IDLE_TIMEOUT`] on the socket. The IP allow-list
/// in [`crate::serve_with`] still runs first.
pub fn serve_qfltl(
    state: &crate::StateDir,
    listener: std::net::TcpListener,
    policy: ductei_core::ScopePolicy,
    allow_ips: &[std::net::IpAddr],
    max_conns: Option<usize>,
    identity: &KemKeypair,
    on_conn: impl FnMut(std::net::SocketAddr, io::Result<usize>),
) -> io::Result<()> {
    let root = state.root().to_path_buf();
    crate::serve_with(
        state,
        listener,
        policy,
        allow_ips,
        max_conns,
        on_conn,
        move |stream, ch| {
            let pinned = load_pinned_clients(&root)?;
            stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
            stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
            let encrypted = server_handshake(stream, identity, &pinned)?;
            encrypted.get_ref().set_read_timeout(Some(IDLE_TIMEOUT))?;
            encrypted.get_ref().set_write_timeout(Some(IDLE_TIMEOUT))?;
            ductei_core::transport::serve_stream(encrypted, ch)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qfltl-sync-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// Run the server handshake on a thread against a real loopback socket
    /// and hand back the client end plus the server's result.
    fn with_server<T: Send + 'static>(
        server_kp: KemKeypair,
        pinned_clients: Vec<Vec<u8>>,
        after: impl FnOnce(EncryptedStream<TcpStream>) -> T + Send + 'static,
    ) -> (TcpStream, std::thread::JoinHandle<io::Result<T>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            server_handshake(s, &server_kp, &pinned_clients).map(after)
        });
        let c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (c, h)
    }

    fn channel_pair() -> (SecureChannel, SecureChannel) {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        (
            SecureChannel::from_handshake(Role::Client, &[&a[..], &b[..]], b"t").unwrap(),
            SecureChannel::from_handshake(Role::Server, &[&a[..], &b[..]], b"t").unwrap(),
        )
    }

    #[test]
    fn mutual_handshake_then_envelope_framing_roundtrips() {
        let server_kp = KemKeypair::generate();
        let client_kp = KemKeypair::generate();
        let server_pub = server_kp.public_bytes();
        let body = br#"{"scope":"brain.correction","id":"abc"}"#.to_vec();

        let (c, h) = with_server(server_kp, vec![client_kp.public_bytes()], |mut s| {
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let mut got = vec![0u8; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut got).unwrap();
            got
        });
        let mut client = client_handshake(c, &client_kp, &server_pub).expect("handshake");
        // mirrors write_frame's two writes (length prefix, then JSON body)
        client.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        client.write_all(&body).unwrap();
        assert_eq!(h.join().unwrap().unwrap(), body);
    }

    #[test]
    fn wrong_server_pin_fails_before_client_sends_anything() {
        let server_kp = KemKeypair::generate();
        let client_kp = KemKeypair::generate();
        let wrong = KemKeypair::generate().public_bytes();
        let (c, h) = with_server(server_kp, vec![client_kp.public_bytes()], |_| ());
        let err = client_handshake(c, &client_kp, &wrong).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(h.join().unwrap().is_err(), "server must not accept either");
    }

    #[test]
    fn unpinned_client_is_refused() {
        let server_kp = KemKeypair::generate();
        let server_pub = server_kp.public_bytes();
        let client_kp = KemKeypair::generate();
        let (c, h) = with_server(server_kp, vec![], |_| ());
        // From the client's side this looks exactly like a wrong pin.
        let err = client_handshake(c, &client_kp, &server_pub).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let err = h.join().unwrap().err().expect("server must refuse");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn impostor_claiming_a_pinned_fingerprint_gets_no_session() {
        let server_kp = KemKeypair::generate();
        let server_pub = server_kp.public_bytes();
        let real_client = KemKeypair::generate();
        let impostor = KemKeypair::generate();
        let (c, h) = with_server(server_kp, vec![real_client.public_bytes()], |_| ());
        // Knows the real client's public key (so its fingerprint) but not its
        // private key: cannot recover ss2, so key confirmation fails.
        let r = client_handshake_as(c, &impostor, real_client.fingerprint(), &server_pub);
        assert_eq!(r.err().expect("must fail").kind(), io::ErrorKind::PermissionDenied);
        assert!(h.join().unwrap().is_err(), "server must not hand an impostor a session");
    }

    /// Review finding 1: a hello with a pinned (public) fingerprint and a
    /// junk ciphertext, then silence, used to complete the server handshake
    /// and hang serve forever. It must now fail within the read timeout.
    #[test]
    fn silent_client_cannot_complete_the_server_handshake() {
        let server_kp = KemKeypair::generate();
        let client_kp = KemKeypair::generate();
        let (mut c, h) = with_server(server_kp, vec![client_kp.public_bytes()], |_| ());
        let ek_e = KemKeypair::generate().public_bytes();
        let hello = [HS_MAGIC.as_slice(), &client_kp.fingerprint(), &[0xABu8; ML_KEM_768_CT_LEN], &ek_e].concat();
        write_raw_frame(&mut c, &hello).unwrap();
        let start = Instant::now();
        let r = h.join().unwrap();
        assert!(r.is_err(), "server must not complete a handshake without the client's proof");
        assert!(start.elapsed() < Duration::from_secs(4), "must give up at the read timeout");
        drop(c);
    }

    /// Tees every byte a stream sends and receives, to play a passive
    /// eavesdropper who records the whole connection.
    struct Recorder<S> {
        inner: S,
        sent: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        recvd: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl<S: Read> Read for Recorder<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.recvd.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }
    impl<S: Write> Write for Recorder<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.sent.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    /// Forward secrecy: record a whole session, then hand the attacker BOTH
    /// long-term private keys. They recover ss1 and ss2 but not ss3, so the
    /// recorded data record still won't open.
    #[test]
    fn recorded_session_stays_sealed_after_both_identity_keys_leak() {
        let server_kp = KemKeypair::generate();
        let client_kp = KemKeypair::generate();
        let server_pub = server_kp.public_bytes();
        let server_seed = server_kp.seed_bytes();

        let (c, h) = with_server(server_kp, vec![client_kp.public_bytes()], |mut s| {
            let mut got = [0u8; 6];
            s.read_exact(&mut got).unwrap();
            got
        });
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recvd = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rec = Recorder { inner: c, sent: sent.clone(), recvd: recvd.clone() };
        let mut client = client_handshake(rec, &client_kp, &server_pub).expect("handshake");
        client.write_all(b"secret").unwrap();
        assert_eq!(&h.join().unwrap().unwrap(), b"secret");

        // Split the recording back into frames.
        fn frames(mut b: &[u8]) -> Vec<Vec<u8>> {
            let mut out = vec![];
            while b.len() >= 4 {
                let n = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
                out.push(b[4..4 + n].to_vec());
                b = &b[4 + n..];
            }
            out
        }
        let up = frames(&sent.lock().unwrap());
        let down = frames(&recvd.lock().unwrap());
        // up: hello, client proof, data record; down: reply, server confirm
        assert_eq!(up.len(), 3);
        let hello = &up[0];
        let (ct1, ek_e) = (&hello[40..40 + ML_KEM_768_CT_LEN], &hello[40 + ML_KEM_768_CT_LEN..]);
        let (ct2, ct3) = down[0].split_at(ML_KEM_768_CT_LEN);
        let tr = transcript(&client_kp.fingerprint(), &fingerprint(&server_pub), ct1, ek_e, ct2, ct3);

        // Attacker with both long-term keys.
        let stolen_server = KemKeypair::from_seed_bytes(&server_seed).unwrap();
        let ss1 = stolen_server.decapsulate(ct1).unwrap();
        let ss2 = client_kp.decapsulate(ct2).unwrap();
        // Best available guesses for ss3: decapsulate ct3 with either static key.
        for guess in [stolen_server.decapsulate(ct3).unwrap(), client_kp.decapsulate(ct3).unwrap()] {
            let mut ch = SecureChannel::from_handshake(Role::Server, &[&ss1[..], &ss2[..], &guess[..]], &tr).unwrap();
            assert!(ch.open(&up[1]).is_err(), "client proof must not open without dk_e");
        }
        // Without ss3 at all (the pre-FS protocol) also fails.
        let mut ch = SecureChannel::from_handshake(Role::Server, &[&ss1[..], &ss2[..]], &tr).unwrap();
        assert!(ch.open(&up[1]).is_err());
    }

    /// An active attacker who swaps the client's ephemeral key in transit
    /// (to learn ss3 itself) breaks the transcript: the client refuses the
    /// server's confirmation and the server never accepts the session.
    #[test]
    fn swapped_ephemeral_key_is_detected() {
        let server_kp = KemKeypair::generate();
        let client_kp = KemKeypair::generate();
        let server_pub = server_kp.public_bytes();
        let (srv, h) = with_server(server_kp, vec![client_kp.public_bytes()], |_| ());

        // MITM proxy: forwards both ways, replacing ek_e in the hello.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = l.local_addr().unwrap();
        let p = std::thread::spawn(move || {
            let (mut from_client, _) = l.accept().unwrap();
            let mut to_server = srv;
            let mut hello = read_raw_frame(&mut from_client, 8192).unwrap();
            let attacker_ek = KemKeypair::generate().public_bytes();
            hello[40 + ML_KEM_768_CT_LEN..].copy_from_slice(&attacker_ek);
            write_raw_frame(&mut to_server, &hello).unwrap();
            let mut s2 = to_server.try_clone().unwrap();
            let mut c2 = from_client.try_clone().unwrap();
            let up = std::thread::spawn(move || {
                let _ = io::copy(&mut c2, &mut s2);
                let _ = s2.shutdown(std::net::Shutdown::Write);
            });
            let _ = io::copy(&mut to_server, &mut from_client);
            let _ = from_client.shutdown(std::net::Shutdown::Write);
            let _ = up.join();
        });

        let c = TcpStream::connect(proxy_addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let err = client_handshake(c, &client_kp, &server_pub).err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(h.join().unwrap().is_err(), "server must not accept a spliced handshake");
        let _ = p.join();
    }

    /// Review finding 2, at the stream level: a replayed record and a record
    /// reflected back at its sender both fail to open.
    #[test]
    fn encrypted_stream_rejects_replayed_and_reflected_records() {
        let (c, s) = channel_pair();
        let mut client = EncryptedStream::new(Vec::<u8>::new(), c);
        client.write_all(b"hello").unwrap();
        let wire = client.inner.clone();

        let mut server = EncryptedStream::new(io::Cursor::new([wire.clone(), wire.clone()].concat()), s);
        let mut got = [0u8; 5];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
        assert!(server.read(&mut got).is_err(), "replayed record must be rejected");

        let (c2, _) = channel_pair();
        let mut reflected = EncryptedStream::new(io::Cursor::new(wire), c2);
        assert!(reflected.read(&mut got).is_err(), "reflected record must be rejected");
    }

    #[test]
    fn identity_persists_and_pins_are_role_separated() {
        let dir = tmp("ident");
        let kp1 = load_or_generate_identity(&dir).unwrap();
        let kp2 = load_or_generate_identity(&dir).unwrap();
        assert_eq!(kp1.public_bytes(), kp2.public_bytes());
        assert_eq!(fs::read(public_key_path(&dir)).unwrap(), kp1.public_bytes());

        assert!(pinned_server_key(&dir, "xing-laptop").unwrap().is_none());
        assert!(pin_key(&dir, PinRole::Server, "junk", b"not a key", false).is_err());
        let peer = KemKeypair::generate();
        let fp = pin_key(&dir, PinRole::Server, "xing-laptop", &peer.public_bytes(), false).unwrap();
        assert_eq!(fp, peer.fingerprint());
        assert_eq!(pinned_server_key(&dir, "xing-laptop").unwrap().unwrap(), peer.public_bytes());
        // Review finding 3: a server pin is NOT an accepted client.
        assert!(load_pinned_clients(&dir).unwrap().is_empty());
        pin_key(&dir, PinRole::Client, "xing-laptop", &peer.public_bytes(), false).unwrap();
        assert_eq!(load_pinned_clients(&dir).unwrap(), vec![peer.public_bytes()]);

        // Re-pinning: same key is a no-op, a different key needs `replace`.
        pin_key(&dir, PinRole::Server, "xing-laptop", &peer.public_bytes(), false).unwrap();
        let other = KemKeypair::generate();
        let err = pin_key(&dir, PinRole::Server, "xing-laptop", &other.public_bytes(), false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(pinned_server_key(&dir, "xing-laptop").unwrap().unwrap(), peer.public_bytes());
        pin_key(&dir, PinRole::Server, "xing-laptop", &other.public_bytes(), true).unwrap();
        assert_eq!(pinned_server_key(&dir, "xing-laptop").unwrap().unwrap(), other.public_bytes());

        assert!(!legacy_pins_present(&dir));
        fs::create_dir_all(dir.join("qfltl").join("known_peers")).unwrap();
        fs::write(dir.join("qfltl").join("known_peers").join("old.pub"), peer.public_bytes()).unwrap();
        assert!(legacy_pins_present(&dir));

        if keystore::AVAILABLE {
            assert!(!dir.join("qfltl").join("identity.seed").exists(), "no plaintext seed on Windows");
            let w = fs::read(dir.join("qfltl").join("identity.seed.dpapi")).unwrap();
            assert_ne!(w, kp1.seed_bytes(), "seed must be wrapped, not stored raw");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Review finding 4a: serve and push starting together on a fresh state
    /// dir must end up with one identity, not two that overwrite each other.
    #[test]
    fn identity_creation_race_yields_one_identity() {
        let dir = tmp("race");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let d = dir.clone();
                std::thread::spawn(move || load_or_generate_identity(&d).unwrap().public_bytes())
            })
            .collect();
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]), "all racers must agree on one identity");
        assert_eq!(load_or_generate_identity(&dir).unwrap().public_bytes(), keys[0]);
        assert_eq!(fs::read(public_key_path(&dir)).unwrap(), keys[0]);
        let leftovers = fs::read_dir(dir.join("qfltl"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temp files left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_plaintext_seed_is_migrated() {
        let dir = tmp("migrate");
        let old = KemKeypair::generate();
        fs::create_dir_all(dir.join("qfltl")).unwrap();
        fs::write(dir.join("qfltl").join("identity.seed"), old.seed_bytes()).unwrap();
        let kp = load_or_generate_identity(&dir).unwrap();
        assert_eq!(kp.public_bytes(), old.public_bytes(), "same identity after migration");
        if keystore::AVAILABLE {
            assert!(!dir.join("qfltl").join("identity.seed").exists());
            assert!(dir.join("qfltl").join("identity.seed.dpapi").exists());
            let again = load_or_generate_identity(&dir).unwrap();
            assert_eq!(again.public_bytes(), old.public_bytes());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Full `push_once_qfltl` -> `serve_qfltl` round trip over loopback TCP:
    /// refused with no server pin, refused by the server with no client pin,
    /// delivered once both sides are pinned under the right roles.
    #[test]
    fn two_node_push_serve_over_qfltl() {
        use ductei_core::{scoped, ScopePolicy};

        let a = crate::StateDir::open(tmp("e2e-a")).unwrap();
        let b = crate::StateDir::open(tmp("e2e-b")).unwrap();
        let na = a.node_id().unwrap();
        a.local_channel(ScopePolicy::new().allow("brain.correction"))
            .unwrap()
            .send(scoped("k1", &["brain.correction"], na, 1, b"one"))
            .unwrap();

        let a_id = load_or_generate_identity(a.root()).unwrap();
        let b_id = load_or_generate_identity(b.root()).unwrap();

        let serve_pass = || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let b2 = b.clone();
            let id = KemKeypair::from_seed_bytes(&b_id.seed_bytes()).unwrap();
            let h = std::thread::spawn(move || {
                let mut res = None;
                serve_qfltl(&b2, listener, ScopePolicy::new().allow("brain.correction"), &[], Some(1), &id, |_, r| {
                    res = Some(r.is_ok())
                })
                .unwrap();
                res
            });
            (addr, h)
        };
        let inbound = || {
            ductei_core::LogStore::open(b.inbound_log())
                .map(|l| l.replay(0).unwrap().0.len())
                .unwrap_or(0)
        };

        // 1. No server pin on A: refused without dialing.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert!(push_once_qfltl(&a, &dead).unwrap().interrupted);

        // 2. A pins B as a server, but B hasn't pinned A as a client.
        let (addr, h) = serve_pass();
        pin_key(a.root(), PinRole::Server, &addr, &b_id.public_bytes(), false).unwrap();
        let r = push_once_qfltl(&a, &addr).unwrap();
        assert!(r.interrupted && r.delivered == 0);
        assert_eq!(h.join().unwrap(), Some(false));
        assert_eq!(inbound(), 0);

        // 2b. B pinning A under the WRONG role (server) still refuses it.
        pin_key(b.root(), PinRole::Server, "xing-pc", &a_id.public_bytes(), false).unwrap();
        let (addr, h) = serve_pass();
        pin_key(a.root(), PinRole::Server, &addr, &b_id.public_bytes(), false).unwrap();
        assert!(push_once_qfltl(&a, &addr).unwrap().interrupted);
        assert_eq!(h.join().unwrap(), Some(false));
        assert_eq!(inbound(), 0);

        // 3. Both pinned under the right roles: delivered end to end.
        pin_key(b.root(), PinRole::Client, "xing-pc", &a_id.public_bytes(), false).unwrap();
        let (addr, h) = serve_pass();
        pin_key(a.root(), PinRole::Server, &addr, &b_id.public_bytes(), false).unwrap();
        let r = push_once_qfltl(&a, &addr).unwrap();
        assert_eq!(h.join().unwrap(), Some(true));
        assert_eq!(r.delivered, 1, "the envelope must round-trip through the encrypted path");
        let (got, _) = ductei_core::LogStore::open(b.inbound_log()).unwrap().replay(0).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, "k1");
    }
}
