# CGGMP24 runtime selection and optional Rust build

Companion to **`API_IMPLEMENTATION.md`** for clients and operators touching **secp256k1** MPC after **runtime ECDSA protocol selection** was added to **mpc-auth**.

## HTTP / signed JSON

- **`POST /keyGenRequest`** optional body field **`ecdsaMpcProtocol`** (also mirrored in protobuf / list responses as **`EcdsaMpcProtocol`**):
  - Omit or **`"gg18"`** — default **GG18-style** ECDSA DKG (vendored tss-lib), production path today.
  - **`"cggmp24"`** — selects the **CGGMP24** track (Lockness). **Distributed keygen/signing are not finished** in mpc-auth yet; the node rejects **presign** and **sign** creation for such keys until workers ship. Prefer **GG18** for live traffic until **`docs-internal/CGGMP24_ROADMAP.md`** phases complete.
- **Ed25519** keygen **ignores** `ecdsaMpcProtocol` (EdDSA multiparty stack, not GG18 ECDSA).

When calling management-key endpoints, **include every field you send** in the signed JSON (same as today); if you add `ecdsaMpcProtocol`, it must be inside the signed payload.

## Version diagnostics

- **`GET /version`** `data` may include **`cggmp24UpstreamGitRev`**: 40-hex **git revision** of the Lockness **`cggmp21`** pin **if** the binary was built with **Go `-tags rust`** and **`libcggmp24_mpc_auth_ffi`** is linked. Default Docker/dev builds often omit it (**empty string**). Use it to confirm which upstream revision an image was compiled against.

## Codegen / OpenAPI

Regenerate or hand-merge from **mpc-auth** `docs/swagger.json` / `docs/swagger.yaml` if your client uses **`node.KeyGenRequestPost`** / version response shapes — add optional **`ecdsaMpcProtocol`** and **`cggmp24UpstreamGitRev`**.

## Maintainer build (Rust FFI smoke)

From **mpc-auth** repo: **`make rust-ffi`** then **`make test_rust_ffi`** (or CI job **`cggmp24-ffi`**). This does **not** replace full integration tests against a running cluster.

**See also:** `docs/references/API_IMPLEMENTATION.md` (keygen, version, presign/sign notes for CGGMP24).
