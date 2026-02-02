import sodium from 'libsodium-wrappers-sumo'

await sodium.ready

const CHUNK_SIZE = 8 * 1024 * 1024

export function createMasterKeyFromPassword(password, salt = null) {
  if (!salt) {
    salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES)
  }

  const masterKey = sodium.crypto_pwhash(
    32,
    password,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
    sodium.crypto_pwhash_MEMLIMIT_SENSITIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  )

  return { masterKey, salt }
}

export function createKeyEncryptionKey(masterKey) {
  return sodium.crypto_kdf_derive_from_key(32, 1, 'kek_ctx_', masterKey)
}

export function generateDataKey() {
  return sodium.randombytes_buf(32)
}

export function encryptDataKey(dataKey, kek) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(dataKey, null, null, nonce, kek)
  const result = new Uint8Array(nonce.length + encrypted.length)
  result.set(nonce)
  result.set(encrypted, nonce.length)
  return result
}

export function decryptDataKey(encryptedDataKey, kek) {
  const nonceLength = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = encryptedDataKey.slice(0, nonceLength)
  const encrypted = encryptedDataKey.slice(nonceLength)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, encrypted, null, nonce, kek)
}

export function deriveVaultKey(dataKey, vaultId) {
  const vaultIdBytes = sodium.from_hex(vaultId)
  return sodium.crypto_generichash(32, vaultIdBytes, dataKey)
}

export function deriveFileKey(vaultKey, fileId) {
  const fileIdBytes = sodium.from_hex(fileId)
  return sodium.crypto_generichash(32, fileIdBytes, vaultKey)
}

export function encryptChunk(chunk, fileKey, chunkIndex) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const ad = new Uint8Array(4)
  new DataView(ad.buffer).setUint32(0, chunkIndex, false)
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(chunk, ad, null, nonce, fileKey)
  return { encrypted, nonce }
}

export function decryptChunk(encrypted, nonce, fileKey, chunkIndex) {
  const ad = new Uint8Array(4)
  new DataView(ad.buffer).setUint32(0, chunkIndex, false)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, encrypted, ad, nonce, fileKey)
}

export function encryptIndex(data, kek) {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const indexKey = sodium.crypto_kdf_derive_from_key(32, 2, 'idx_ctx_', kek)
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(data, null, null, nonce, indexKey)
  const result = new Uint8Array(nonce.length + encrypted.length)
  result.set(nonce)
  result.set(encrypted, nonce.length)
  return result
}

export function decryptIndex(data, kek) {
  const nonceLength = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = data.slice(0, nonceLength)
  const encrypted = data.slice(nonceLength)
  const indexKey = sodium.crypto_kdf_derive_from_key(32, 2, 'idx_ctx_', kek)
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, encrypted, null, nonce, indexKey)
}

export function deriveOpKey(kek) {
  return sodium.crypto_kdf_derive_from_key(32, 3, 'ops_ctx_', kek)
}

export function encryptOp(op, kek) {
  const opKey = deriveOpKey(kek)
  const data = new TextEncoder().encode(JSON.stringify(op))
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(data, null, null, nonce, opKey)
  const result = new Uint8Array(nonce.length + encrypted.length)
  result.set(nonce)
  result.set(encrypted, nonce.length)
  return result
}

export function decryptOp(data, kek) {
  const opKey = deriveOpKey(kek)
  const nonceLength = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  const nonce = data.slice(0, nonceLength)
  const encrypted = data.slice(nonceLength)
  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, encrypted, null, nonce, opKey)
  return JSON.parse(new TextDecoder().decode(decrypted))
}

export function chunkFile(data) {
  const chunks = []
  const totalChunks = Math.ceil(data.length / CHUNK_SIZE)

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE
    const end = Math.min(start + CHUNK_SIZE, data.length)
    chunks.push(data.slice(start, end))
  }

  return chunks
}

export function generateId() {
  return sodium.to_hex(sodium.randombytes_buf(16))
}

export { sodium, CHUNK_SIZE }
