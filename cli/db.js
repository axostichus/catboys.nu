import { Database } from 'bun:sqlite'
import { secrets } from 'bun'
import path from 'path'
import os from 'os'
import fs from 'fs'

const CONFIG_DIR = path.join(os.homedir(), '.encrypted-files')
const DB_PATH = path.join(CONFIG_DIR, 'cache.sqlite')
const SERVICE_NAME = 'nu.catboys.cli'

if (!fs.existsSync(CONFIG_DIR)) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true })
}

let db = null

function initDatabase() {
  if (db) return db

  db = new Database(DB_PATH)
  db.run('PRAGMA journal_mode = WAL;')
  db.run('PRAGMA foreign_keys = ON;')

  db.run(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT NOT NULL UNIQUE PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)

  db.run(`
    CREATE TABLE IF NOT EXISTS pending_ops (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op TEXT NOT NULL,
      createdAt TEXT NOT NULL
    )
  `)

  db.run(`
    CREATE TABLE IF NOT EXISTS vaults (
      id TEXT NOT NULL UNIQUE PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      createdAt TEXT NOT NULL
    )
  `)

  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id TEXT NOT NULL UNIQUE PRIMARY KEY,
      vaultId TEXT NOT NULL,
      path TEXT NOT NULL,
      size INTEGER NOT NULL,
      mime TEXT,
      hash TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL,
      FOREIGN KEY(vaultId) REFERENCES vaults(id),
      UNIQUE(vaultId, path)
    )
  `)

  db.run(`
    CREATE TABLE IF NOT EXISTS chunks (
      id TEXT NOT NULL UNIQUE PRIMARY KEY,
      fileId TEXT NOT NULL,
      chunkIndex INTEGER NOT NULL,
      nonce BLOB NOT NULL,
      size INTEGER NOT NULL,
      FOREIGN KEY(fileId) REFERENCES files(id) ON DELETE CASCADE
    )
  `)

  db.run(`CREATE INDEX IF NOT EXISTS idx_files_vaultId ON files(vaultId)`)
  db.run(`CREATE INDEX IF NOT EXISTS idx_files_path ON files(vaultId, path)`)
  db.run(`CREATE INDEX IF NOT EXISTS idx_chunks_fileId ON chunks(fileId)`)

  return db
}

export function getDatabase() {
  return initDatabase()
}

export function beginTransaction() {
  const db = getDatabase()
  db.run('BEGIN IMMEDIATE')
}

export function commitTransaction() {
  const db = getDatabase()
  db.run('COMMIT')
}

export function rollbackTransaction() {
  const db = getDatabase()
  try {
    db.run('ROLLBACK')
  } catch (e) {
  }
}

export function getSyncedVersion() {
  const db = getDatabase()
  const row = db.prepare('SELECT value FROM meta WHERE key = $key').get({ $key: 'syncedVersion' })
  return row ? parseInt(row.value) : 0
}

export function setSyncedVersion(version) {
  const db = getDatabase()
  db.run('INSERT OR REPLACE INTO meta (key, value) VALUES ($key, $value)', {
    $key: 'syncedVersion',
    $value: version.toString()
  })
}

export function getDeviceId() {
  const db = getDatabase()
  let row = db.prepare('SELECT value FROM meta WHERE key = $key').get({ $key: 'deviceId' })
  if (!row) {
    const deviceId = crypto.randomUUID()
    db.run('INSERT INTO meta (key, value) VALUES ($key, $value)', {
      $key: 'deviceId',
      $value: deviceId
    })
    return deviceId
  }
  return row.value
}

export function addPendingOp(op) {
  const db = getDatabase()
  db.run('INSERT INTO pending_ops (op, createdAt) VALUES ($op, $createdAt)', {
    $op: JSON.stringify(op),
    $createdAt: new Date().toISOString()
  })
}

export function getPendingOps() {
  const db = getDatabase()
  const rows = db.prepare('SELECT id, op FROM pending_ops ORDER BY id ASC').all()
  return rows.map(r => ({ id: r.id, op: JSON.parse(r.op) }))
}

export function clearPendingOps(upToId) {
  const db = getDatabase()
  db.run('DELETE FROM pending_ops WHERE id <= $id', { $id: upToId })
}

export function clearAllPendingOps() {
  const db = getDatabase()
  db.run('DELETE FROM pending_ops')
}

export function getEncryptedDataKey() {
  const db = getDatabase()
  const row = db.prepare('SELECT value FROM meta WHERE key = $key').get({ $key: 'dataKey' })
  return row ? row.value : null
}

export function setEncryptedDataKey(encryptedDataKeyBase64) {
  const db = getDatabase()
  db.run('INSERT OR REPLACE INTO meta (key, value) VALUES ($key, $value)', {
    $key: 'dataKey',
    $value: encryptedDataKeyBase64
  })
}

export function resetDatabase() {
  if (db) {
    db.close()
    db = null
  }
  if (fs.existsSync(DB_PATH)) {
    fs.unlinkSync(DB_PATH)
  }
  const walPath = DB_PATH + '-wal'
  const shmPath = DB_PATH + '-shm'
  if (fs.existsSync(walPath)) fs.unlinkSync(walPath)
  if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath)
  initDatabase()
}

export async function getConfig() {
  const accountNumber = await secrets.get({ service: SERVICE_NAME, name: 'account-number' })
  if (!accountNumber) return null

  const token = await secrets.get({ service: SERVICE_NAME, name: 'token' })
  const salt = await secrets.get({ service: SERVICE_NAME, name: 'salt' })
  const kek = await secrets.get({ service: SERVICE_NAME, name: 'kek' })

  return { accountNumber, token, salt, kek }
}

export async function saveConfig(config) {
  if (config.accountNumber !== undefined) {
    if (config.accountNumber) {
      await secrets.set({ service: SERVICE_NAME, name: 'account-number', value: config.accountNumber })
    } else {
      await secrets.delete({ service: SERVICE_NAME, name: 'account-number' })
    }
  }
  if (config.token !== undefined) {
    if (config.token) {
      await secrets.set({ service: SERVICE_NAME, name: 'token', value: config.token })
    } else {
      await secrets.delete({ service: SERVICE_NAME, name: 'token' })
    }
  }
  if (config.salt !== undefined) {
    if (config.salt) {
      await secrets.set({ service: SERVICE_NAME, name: 'salt', value: config.salt })
    } else {
      await secrets.delete({ service: SERVICE_NAME, name: 'salt' })
    }
  }
  if (config.kek !== undefined) {
    if (config.kek) {
      await secrets.set({ service: SERVICE_NAME, name: 'kek', value: config.kek })
    } else {
      await secrets.delete({ service: SERVICE_NAME, name: 'kek' })
    }
  }
}

export async function clearConfig() {
  await secrets.delete({ service: SERVICE_NAME, name: 'account-number' })
  await secrets.delete({ service: SERVICE_NAME, name: 'token' })
  await secrets.delete({ service: SERVICE_NAME, name: 'salt' })
  await secrets.delete({ service: SERVICE_NAME, name: 'kek' })
}

export function createVault(vault) {
  const db = getDatabase()
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO vaults (id, name, createdAt)
    VALUES ($id, $name, $createdAt)
  `)
  stmt.run({
    $id: vault.id,
    $name: vault.name,
    $createdAt: vault.createdAt
  })
}

export function getVaultByName(name) {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM vaults WHERE name = $name')
  return stmt.get({ $name: name })
}

export function getVaultById(id) {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM vaults WHERE id = $id')
  return stmt.get({ $id: id })
}

export function listVaults() {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM vaults ORDER BY name ASC')
  return stmt.all()
}

export function deleteVaultFromCache(id) {
  const db = getDatabase()
  db.run('DELETE FROM chunks WHERE fileId IN (SELECT id FROM files WHERE vaultId = $vaultId)', { $vaultId: id })
  db.run('DELETE FROM files WHERE vaultId = $vaultId', { $vaultId: id })
  db.run('DELETE FROM vaults WHERE id = $id', { $id: id })
}

export function addFile(file) {
  const db = getDatabase()
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO files (id, vaultId, path, size, mime, hash, createdAt, updatedAt)
    VALUES ($id, $vaultId, $path, $size, $mime, $hash, $createdAt, $updatedAt)
  `)
  stmt.run({
    $id: file.id,
    $vaultId: file.vaultId,
    $path: file.path,
    $size: file.size,
    $mime: file.mime,
    $hash: file.hash,
    $createdAt: file.createdAt,
    $updatedAt: file.updatedAt
  })
}

export function addChunk(chunk) {
  const db = getDatabase()
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO chunks (id, fileId, chunkIndex, nonce, size)
    VALUES ($id, $fileId, $chunkIndex, $nonce, $size)
  `)
  stmt.run({
    $id: chunk.id,
    $fileId: chunk.fileId,
    $chunkIndex: chunk.chunkIndex,
    $nonce: chunk.nonce,
    $size: chunk.size
  })
}

export function getFileByPath(vaultId, filePath) {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM files WHERE vaultId = $vaultId AND path = $path')
  return stmt.get({ $vaultId: vaultId, $path: filePath })
}

export function getFileById(id) {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM files WHERE id = $id')
  return stmt.get({ $id: id })
}

export function getChunksByFileId(fileId) {
  const db = getDatabase()
  const stmt = db.prepare('SELECT * FROM chunks WHERE fileId = $fileId ORDER BY chunkIndex ASC')
  return stmt.all({ $fileId: fileId })
}

export function listFiles(vaultId, prefix = null) {
  const db = getDatabase()
  if (prefix) {
    const stmt = db.prepare('SELECT * FROM files WHERE vaultId = $vaultId AND path LIKE $prefix ORDER BY path ASC')
    return stmt.all({ $vaultId: vaultId, $prefix: prefix + '%' })
  }
  const stmt = db.prepare('SELECT * FROM files WHERE vaultId = $vaultId ORDER BY path ASC')
  return stmt.all({ $vaultId: vaultId })
}

export function deleteFileFromCache(id) {
  const db = getDatabase()
  db.run('DELETE FROM chunks WHERE fileId = $id', { $id: id })
  db.run('DELETE FROM files WHERE id = $id', { $id: id })
}

export function renameFileInCache(id, newPath) {
  const db = getDatabase()
  const now = new Date().toISOString()
  db.run('UPDATE files SET path = $path, updatedAt = $updatedAt WHERE id = $id', {
    $id: id,
    $path: newPath,
    $updatedAt: now
  })
}

export function clearCache() {
  const db = getDatabase()
  db.run('DELETE FROM chunks')
  db.run('DELETE FROM files')
  db.run('DELETE FROM vaults')
}

export function buildSnapshot() {
  const db = getDatabase()
  const vaults = db.prepare('SELECT * FROM vaults').all()
  const files = db.prepare('SELECT * FROM files').all()
  const chunks = db.prepare('SELECT id, fileId, chunkIndex, nonce, size FROM chunks').all()

  return {
    type: 'snapshot',
    timestamp: Date.now(),
    deviceId: getDeviceId(),
    vaults,
    files,
    chunks: chunks.map(c => ({
      ...c,
      nonce: Buffer.from(c.nonce).toString('base64')
    }))
  }
}

export function applySnapshot(snapshot) {
  const db = getDatabase()

  beginTransaction()
  try {
    db.run('DELETE FROM chunks')
    db.run('DELETE FROM files')
    db.run('DELETE FROM vaults')

    for (const vault of snapshot.vaults || []) {
      db.run(`INSERT INTO vaults (id, name, createdAt) VALUES ($id, $name, $createdAt)`, {
        $id: vault.id,
        $name: vault.name,
        $createdAt: vault.createdAt
      })
    }

    for (const file of snapshot.files || []) {
      db.run(`INSERT INTO files (id, vaultId, path, size, mime, hash, createdAt, updatedAt) 
              VALUES ($id, $vaultId, $path, $size, $mime, $hash, $createdAt, $updatedAt)`, {
        $id: file.id,
        $vaultId: file.vaultId,
        $path: file.path,
        $size: file.size,
        $mime: file.mime || null,
        $hash: file.hash || null,
        $createdAt: file.createdAt,
        $updatedAt: file.updatedAt
      })
    }

    for (const chunk of snapshot.chunks || []) {
      const nonce = typeof chunk.nonce === 'string'
        ? Buffer.from(chunk.nonce, 'base64')
        : chunk.nonce
      db.run(`INSERT INTO chunks (id, fileId, chunkIndex, nonce, size) 
              VALUES ($id, $fileId, $chunkIndex, $nonce, $size)`, {
        $id: chunk.id,
        $fileId: chunk.fileId,
        $chunkIndex: chunk.chunkIndex,
        $nonce: nonce,
        $size: chunk.size
      })
    }

    commitTransaction()
  } catch (err) {
    rollbackTransaction()
    throw err
  }
}

export function applyOp(op) {
  const db = getDatabase()

  switch (op.type) {
    case 'snapshot':
      applySnapshot(op)
      break

    case 'create_vault':
      db.run(`INSERT OR REPLACE INTO vaults (id, name, createdAt) VALUES ($id, $name, $createdAt)`, {
        $id: op.vault.id,
        $name: op.vault.name,
        $createdAt: op.vault.createdAt
      })
      break

    case 'delete_vault':
      db.run('DELETE FROM chunks WHERE fileId IN (SELECT id FROM files WHERE vaultId = $vaultId)', { $vaultId: op.vaultId })
      db.run('DELETE FROM files WHERE vaultId = $vaultId', { $vaultId: op.vaultId })
      db.run('DELETE FROM vaults WHERE id = $id', { $id: op.vaultId })
      break

    case 'create_file':
      db.run(`INSERT OR REPLACE INTO files (id, vaultId, path, size, mime, hash, createdAt, updatedAt)
              VALUES ($id, $vaultId, $path, $size, $mime, $hash, $createdAt, $updatedAt)`, {
        $id: op.file.id,
        $vaultId: op.file.vaultId,
        $path: op.file.path,
        $size: op.file.size,
        $mime: op.file.mime || null,
        $hash: op.file.hash || null,
        $createdAt: op.file.createdAt,
        $updatedAt: op.file.updatedAt
      })

      for (const chunk of op.chunks || []) {
        const nonce = typeof chunk.nonce === 'string'
          ? Buffer.from(chunk.nonce, 'base64')
          : chunk.nonce
        db.run(`INSERT OR REPLACE INTO chunks (id, fileId, chunkIndex, nonce, size) 
                VALUES ($id, $fileId, $chunkIndex, $nonce, $size)`, {
          $id: chunk.id,
          $fileId: op.file.id,
          $chunkIndex: chunk.chunkIndex,
          $nonce: nonce,
          $size: chunk.size
        })
      }
      break

    case 'delete_file':
      db.run('DELETE FROM chunks WHERE fileId = $id', { $id: op.fileId })
      db.run('DELETE FROM files WHERE id = $id', { $id: op.fileId })
      break

    case 'rename_file':
      db.run('UPDATE files SET path = $path, updatedAt = $updatedAt WHERE id = $id', {
        $id: op.fileId,
        $path: op.newPath,
        $updatedAt: op.updatedAt || new Date().toISOString()
      })
      break
  }
}

initDatabase()

export { db }
