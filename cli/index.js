#!/usr/bin/env bun
import { program } from 'commander'
import fs from 'fs'
import path from 'path'
import readline from 'readline'
import { v2 as webdav } from 'webdav-server'
import { createAccount, login, logout, getAccountInfo, uploadChunk, downloadChunk, deleteChunk, getIndexVersion, getOps, pushOps, compactOps, downloadChunksParallel, uploadChunksParallel } from './api.js'
import { getConfig, saveConfig, clearConfig, resetDatabase, getSyncedVersion, setSyncedVersion, getDeviceId, addPendingOp, getPendingOps, clearPendingOps, clearAllPendingOps, getEncryptedDataKey, setEncryptedDataKey, beginTransaction, commitTransaction, rollbackTransaction, createVault, getVaultByName, getVaultById, listVaults, deleteVaultFromCache, addFile as addFileToDb, addChunk, getFileByPath, getFileById, getChunksByFileId, listFiles, deleteFileFromCache, renameFileInCache, clearCache, buildSnapshot, applyOp } from './db.js'
import { createMasterKeyFromPassword, createKeyEncryptionKey, generateDataKey, encryptDataKey, decryptDataKey, deriveVaultKey, deriveFileKey, encryptChunk, decryptChunk, encryptOp, decryptOp, chunkFile, generateId, sodium } from './crypto.js'

function promptPassword(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    })

    process.stdout.write(question)

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true)
    }

    let password = ''

    const onData = (char) => {
      const c = char.toString()

      if (c === '\n' || c === '\r' || c === '\u0004') {
        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false)
        }
        process.stdin.removeListener('data', onData)
        process.stdout.write('\n')
        rl.close()
        resolve(password)
      } else if (c === '\u0003') {
        process.exit(1)
      } else if (c === '\u007F' || c === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1)
        }
      } else {
        password += c
      }
    }

    process.stdin.on('data', onData)
    process.stdin.resume()
  })
}


program
  .name('catboy')
  .description('zero-knowledge encrypted file storage system')

function getDataKey(kek) {
  const kekBytes = typeof kek === 'string' ? sodium.from_base64(kek) : kek
  const encryptedDataKeyBase64 = getEncryptedDataKey()
  if (!encryptedDataKeyBase64) {
    throw new Error('No data key found. Please run `catboy sync` to restore from server, or re-register if this is a new account.')
  }
  const encryptedDataKey = sodium.from_base64(encryptedDataKeyBase64)
  return decryptDataKey(encryptedDataKey, kekBytes)
}

const COMPACT_THRESHOLD = 100

async function syncOps(kek, push = true) {
  const kekBytes = typeof kek === 'string' ? sodium.from_base64(kek) : kek
  const localVersion = getSyncedVersion()

  const remote = await getIndexVersion()

  if (remote.version > localVersion) {
    const needsFullRebuild = remote.compactedUpTo > localVersion
    if (needsFullRebuild) {
      clearCache()
    }

    const sinceVersion = needsFullRebuild ? 0 : localVersion
    const { ops, latestVersion } = await getOps(sinceVersion)

    for (const op of ops) {
      const data = sodium.from_base64(op.data)
      const decrypted = decryptOp(data, kekBytes)
      applyOp(decrypted)
    }

    setSyncedVersion(latestVersion)
  }

  if (push) {
    const pending = getPendingOps()
    if (pending.length > 0) {
      const encryptedOps = pending.map(p => ({
        data: sodium.to_base64(encryptOp(p.op, kekBytes))
      }))

      const result = await pushOps(encryptedOps)
      const maxId = pending[pending.length - 1].id
      clearPendingOps(maxId)
      setSyncedVersion(result.latestVersion)

      if (result.latestVersion > COMPACT_THRESHOLD) {
        const snapshot = buildSnapshot()
        const encryptedSnapshot = {
          data: sodium.to_base64(encryptOp(snapshot, kekBytes))
        }
        await compactOps(encryptedSnapshot, result.latestVersion)
      }
    }
  }

  return { version: getSyncedVersion() }
}

program
  .command('register')
  .description('Create a new account')
  .action(async () => {
    try {
      const result = await createAccount()
      console.log('Account created successfully!')
      console.log(`Account Number: ${result.accountNumber}`)
      console.log('\nSave your account number - you will need it to login on other devices.')

      const password = await promptPassword('Enter a password to encrypt your files: ')
      if (!password) {
        console.error('Password is required')
        process.exit(1)
      }

      console.log('Deriving encryption keys (this may take a moment)...')
      const { masterKey, salt } = createMasterKeyFromPassword(password)
      const kek = createKeyEncryptionKey(masterKey)

      await saveConfig({
        accountNumber: result.accountNumber,
        token: result.token,
        salt: sodium.to_base64(salt),
        kek: sodium.to_base64(kek)
      })

      resetDatabase()

      const dataKey = generateDataKey()
      const encryptedDataKey = encryptDataKey(dataKey, kek)
      setEncryptedDataKey(sodium.to_base64(encryptedDataKey))

      console.log('Credentials stored in system keychain!')
      console.log(`\nSalt (save this for login on other devices): ${sodium.to_base64(salt)}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('login')
  .description('Login to an existing account')
  .argument('<accountNumber>', 'Your account number')
  .action(async (accountNumber) => {
    try {
      const result = await login(accountNumber)
      console.log('Logged in successfully!')

      const password = await promptPassword('Enter your password: ')
      if (!password) {
        console.error('Password is required')
        process.exit(1)
      }

      const saltInput = prompt('Enter your salt (base64): ')
      if (!saltInput) {
        console.error('Salt is required for login')
        process.exit(1)
      }
      const salt = sodium.from_base64(saltInput)

      console.log('Deriving encryption keys (this may take a moment)...')
      const { masterKey } = createMasterKeyFromPassword(password, salt)
      const kek = createKeyEncryptionKey(masterKey)

      await saveConfig({
        accountNumber,
        token: result.token,
        salt: sodium.to_base64(salt),
        kek: sodium.to_base64(kek)
      })

      resetDatabase()
      await syncOps(sodium.to_base64(kek), false)

      console.log('Credentials stored securely in system keychain!')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('logout')
  .description('Logout and clear local credentials')
  .action(async () => {
    try {
      const config = await getConfig()
      if (!config) {
        console.log('Not logged in.')
        return
      }

      try {
        await logout()
      } catch (e) { }

      await clearConfig()
      resetDatabase()

      console.log('Logged out and local data cleared.')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('change-password')
  .description('Change your encryption password')
  .action(async () => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      const currentPassword = await promptPassword('Enter your current password: ')
      if (!currentPassword) {
        console.error('Current password is required')
        process.exit(1)
      }

      const salt = sodium.from_base64(config.salt)
      const { masterKey: currentMasterKey } = createMasterKeyFromPassword(currentPassword, salt)
      const currentKek = createKeyEncryptionKey(currentMasterKey)

      if (sodium.to_base64(currentKek) !== config.kek) {
        console.error('Current password is incorrect')
        process.exit(1)
      }

      const newPassword = await promptPassword('Enter your new password: ')
      if (!newPassword) {
        console.error('New password is required')
        process.exit(1)
      }

      const confirmPassword = await promptPassword('Confirm your new password: ')
      if (newPassword !== confirmPassword) {
        console.error('Passwords do not match')
        process.exit(1)
      }

      console.log('Deriving new encryption keys (this may take a moment)...')
      const { masterKey: newMasterKey, salt: newSalt } = createMasterKeyFromPassword(newPassword)
      const newKek = createKeyEncryptionKey(newMasterKey)

      const dataKey = getDataKey(currentKek)
      const newEncryptedDataKey = encryptDataKey(dataKey, newKek)
      setEncryptedDataKey(sodium.to_base64(newEncryptedDataKey))

      await saveConfig({
        salt: sodium.to_base64(newSalt),
        kek: sodium.to_base64(newKek)
      })

      await syncOps(sodium.to_base64(newKek), true)

      console.log('Password changed successfully!')
      console.log(`\nNew Salt (save this for login on other devices): ${sodium.to_base64(newSalt)}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('info')
  .description('Show account information')
  .option('--show-salt', 'Display your salt (needed for login on other devices)')
  .action(async (options) => {
    try {
      const config = await getConfig()
      if (!config) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      const info = await getAccountInfo()
      console.log('Account Information:')
      console.log(`  Account Number: ${info.accountNumber}`)
      console.log(`  Created: ${new Date(info.createdAt).toLocaleString()}`)
      console.log(`  Chunks: ${info.chunkCount}`)
      console.log(`  Total Size: ${formatBytes(parseInt(info.totalSize))}`)
      if (options.showSalt) {
        console.log(`\nSalt (save this for login on other devices): ${config.salt}`)
      } else {
        console.log(`\nUse --show-salt to display your salt for device login.`)
      }
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('sync')
  .description('Sync operations with server')
  .action(async () => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      console.log('Syncing...')
      const result = await syncOps(config.kek, true)
      console.log(`Sync complete! Version: ${result.version}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

const vaultCmd = program.command('vault').description('Manage vaults')

vaultCmd
  .command('create')
  .description('Create a new vault')
  .argument('<name>', 'Vault name')
  .action(async (name) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      const existing = getVaultByName(name)
      if (existing) {
        console.error(`Vault "${name}" already exists`)
        process.exit(1)
      }

      const vaultId = generateId()
      const vault = {
        id: vaultId,
        name,
        createdAt: new Date().toISOString()
      }

      createVault(vault)
      addPendingOp({
        type: 'create_vault',
        timestamp: Date.now(),
        deviceId: getDeviceId(),
        vault
      })

      await syncOps(config.kek, true)

      console.log(`Vault "${name}" created!`)
      console.log(`Vault ID: ${vaultId}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

vaultCmd
  .command('list')
  .description('List all vaults')
  .action(async () => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vaults = listVaults()
      if (vaults.length === 0) {
        console.log('No vaults yet. Create one with `catboy vault create <name>`')
        return
      }

      console.log('Vaults:\n')
      for (const vault of vaults) {
        const files = listFiles(vault.id)
        console.log(`  ${vault.name}`)
        console.log(`    ID: ${vault.id}`)
        console.log(`    Files: ${files.length}`)
        console.log(`    Created: ${new Date(vault.createdAt).toLocaleString()}`)
        console.log()
      }
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

vaultCmd
  .command('delete')
  .description('Delete an empty vault')
  .argument('<name>', 'Vault name')
  .action(async (name) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(name)
      if (!vault) {
        console.error(`Vault "${name}" not found`)
        process.exit(1)
      }

      const files = listFiles(vault.id)
      if (files.length > 0) {
        console.error('Vault is not empty. Delete all files first.')
        process.exit(1)
      }

      deleteVaultFromCache(vault.id)
      addPendingOp({
        type: 'delete_vault',
        timestamp: Date.now(),
        deviceId: getDeviceId(),
        vaultId: vault.id
      })

      await syncOps(config.kek, true)

      console.log(`Vault "${name}" deleted!`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('upload')
  .description('Upload and encrypt a file')
  .argument('<vault>', 'Vault name')
  .argument('<key>', 'S3-like key path (e.g., notes/2025/01/file.md)')
  .argument('<file>', 'Path to local file')
  .action(async (vaultName, key, filePath) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(vaultName)
      if (!vault) {
        console.error(`Vault "${vaultName}" not found. Create it with: catboy vault create ${vaultName}`)
        process.exit(1)
      }

      const absolutePath = path.resolve(filePath)
      if (!fs.existsSync(absolutePath)) {
        console.error(`File not found: ${absolutePath}`)
        process.exit(1)
      }

      const existingFile = getFileByPath(vault.id, key)
      if (existingFile) {
        console.error(`File already exists at "${key}" in vault "${vaultName}"`)
        console.error(`Delete it first with: catboy delete ${vaultName} ${key}`)
        process.exit(1)
      }

      const dataKey = getDataKey(config.kek)
      const vaultKey = deriveVaultKey(dataKey, vault.id)
      const fileData = fs.readFileSync(absolutePath)
      const fileId = generateId()
      const fileKey = deriveFileKey(vaultKey, fileId)
      const now = new Date().toISOString()

      console.log(`Uploading to ${vaultName}:${key} (${formatBytes(fileData.length)})...`)

      const chunks = chunkFile(fileData)
      console.log(`Splitting into ${chunks.length} chunk(s)...`)

      console.log('Encrypting chunks...')
      const encryptedChunks = chunks.map((chunk, i) => {
        const { encrypted, nonce } = encryptChunk(chunk, fileKey, i)
        return { encrypted, nonce, index: i }
      })

      console.log('Uploading chunks in parallel...')
      const uploadResults = await uploadChunksParallel(
        encryptedChunks.map(c => c.encrypted),
        12
      )

      const file = {
        id: fileId,
        vaultId: vault.id,
        path: key,
        size: fileData.length,
        mime: null,
        hash: null,
        createdAt: now,
        updatedAt: now
      }

      const chunkRecords = encryptedChunks.map((c, i) => ({
        id: uploadResults[i].id,
        chunkIndex: i,
        nonce: sodium.to_base64(c.nonce),
        size: c.encrypted.length
      }))

      beginTransaction()
      try {
        addFileToDb(file)
        for (const chunk of chunkRecords) {
          addChunk({
            id: chunk.id,
            fileId,
            chunkIndex: chunk.chunkIndex,
            nonce: Buffer.from(sodium.from_base64(chunk.nonce)),
            size: chunk.size
          })
        }
        commitTransaction()
      } catch (err) {
        rollbackTransaction()
        throw err
      }

      addPendingOp({
        type: 'create_file',
        timestamp: Date.now(),
        deviceId: getDeviceId(),
        file,
        chunks: chunkRecords
      })

      await syncOps(config.kek, true)

      console.log(`\nFile uploaded successfully!`)
      console.log(`  Vault: ${vaultName}`)
      console.log(`  Key: ${key}`)
      console.log(`  File ID: ${fileId}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })
program
  .command('download')
  .description('Download and decrypt a file')
  .argument('<vault>', 'Vault name')
  .argument('<key>', 'S3-like key path')
  .argument('[output]', 'Output path (optional, defaults to filename from key)')
  .action(async (vaultName, key, outputPath) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(vaultName)
      if (!vault) {
        console.error(`Vault "${vaultName}" not found`)
        process.exit(1)
      }

      const file = getFileByPath(vault.id, key)
      if (!file) {
        console.error(`File not found: ${vaultName}:${key}`)
        process.exit(1)
      }

      const dataKey = getDataKey(config.kek)
      const vaultKey = deriveVaultKey(dataKey, vault.id)
      const fileKey = deriveFileKey(vaultKey, file.id)
      const chunks = getChunksByFileId(file.id)

      console.log(`Downloading ${vaultName}:${key} (${chunks.length} chunks)...`)

      const chunkIds = chunks.map(c => c.id)
      console.log('Downloading chunks in parallel...')
      const encryptedChunks = await downloadChunksParallel(chunkIds, 12)

      console.log('Decrypting...')
      const decryptedChunks = encryptedChunks.map((encryptedData, i) => {
        const chunk = chunks[i]
        const nonce = new Uint8Array(chunk.nonce)
        const decrypted = decryptChunk(encryptedData, nonce, fileKey, chunk.chunkIndex)
        return Buffer.from(decrypted)
      })

      const output = Buffer.concat(decryptedChunks).slice(0, file.size)
      const finalPath = outputPath || path.basename(key)

      fs.writeFileSync(finalPath, output)
      console.log(`\nFile downloaded to: ${finalPath}`)
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('list')
  .description('List files in a vault')
  .argument('<vault>', 'Vault name')
  .argument('[prefix]', 'Optional key prefix to filter')
  .action(async (vaultName, prefix) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(vaultName)
      if (!vault) {
        console.error(`Vault "${vaultName}" not found`)
        process.exit(1)
      }

      const files = listFiles(vault.id, prefix)
      if (files.length === 0) {
        console.log(prefix
          ? `No files matching prefix "${prefix}" in vault "${vaultName}"`
          : `No files in vault "${vaultName}"`)
        return
      }

      console.log(`Files in ${vaultName}${prefix ? ` (prefix: ${prefix})` : ''}:\n`)
      for (const file of files) {
        const chunks = getChunksByFileId(file.id)
        console.log(`  ${file.path}`)
        console.log(`    Size: ${formatBytes(file.size)}`)
        console.log(`    Chunks: ${chunks.length}`)
        console.log(`    ID: ${file.id}`)
        console.log(`    Updated: ${new Date(file.updatedAt).toLocaleString()}`)
        console.log()
      }
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('delete')
  .description('Delete a file')
  .argument('<vault>', 'Vault name')
  .argument('<key>', 'S3-like key path')
  .action(async (vaultName, key) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(vaultName)
      if (!vault) {
        console.error(`Vault "${vaultName}" not found`)
        process.exit(1)
      }

      const file = getFileByPath(vault.id, key)
      if (!file) {
        console.error(`File not found: ${vaultName}:${key}`)
        process.exit(1)
      }

      const chunks = getChunksByFileId(file.id)
      console.log(`Deleting ${vaultName}:${key} (${chunks.length} chunks)...`)

      for (let i = 0; i < chunks.length; i++) {
        console.log(`  Deleting chunk ${i + 1}/${chunks.length}...`)
        await deleteChunk(chunks[i].id)
      }

      deleteFileFromCache(file.id)
      addPendingOp({
        type: 'delete_file',
        timestamp: Date.now(),
        deviceId: getDeviceId(),
        fileId: file.id
      })

      await syncOps(config.kek, true)

      console.log('File deleted successfully!')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('rename')
  .description('Rename/move a file within a vault')
  .argument('<vault>', 'Vault name')
  .argument('<oldKey>', 'Current S3-like key path')
  .argument('<newKey>', 'New S3-like key path')
  .action(async (vaultName, oldKey, newKey) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const vault = getVaultByName(vaultName)
      if (!vault) {
        console.error(`Vault "${vaultName}" not found`)
        process.exit(1)
      }

      const file = getFileByPath(vault.id, oldKey)
      if (!file) {
        console.error(`File not found: ${vaultName}:${oldKey}`)
        process.exit(1)
      }

      const existingAtNewPath = getFileByPath(vault.id, newKey)
      if (existingAtNewPath) {
        console.error(`A file already exists at: ${vaultName}:${newKey}`)
        process.exit(1)
      }

      console.log(`Renaming ${vaultName}:${oldKey} -> ${newKey}...`)

      const now = new Date().toISOString()
      renameFileInCache(file.id, newKey)
      addPendingOp({
        type: 'rename_file',
        timestamp: Date.now(),
        deviceId: getDeviceId(),
        fileId: file.id,
        newPath: newKey,
        updatedAt: now
      })

      await syncOps(config.kek, true)

      console.log('File renamed successfully!')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}


class EncryptedVaultFileSystem extends webdav.FileSystem {
  constructor(vault, dataKey) {
    super(new webdav.LocalLockManager())
    this.vault = vault
    this.dataKey = dataKey
    this.vaultKey = deriveVaultKey(dataKey, vault.id)
    this.resources = new Map()
    this.properties = new Map()
    this.locks = new Map()
  }

  _lockManager(path, ctx, callback) {
    const pathStr = path.toString()
    if (!this.locks.has(pathStr)) {
      this.locks.set(pathStr, new webdav.LocalLockManager())
    }
    callback(null, this.locks.get(pathStr))
  }

  _propertyManager(path, ctx, callback) {
    const pathStr = path.toString()
    if (!this.properties.has(pathStr)) {
      this.properties.set(pathStr, new webdav.LocalPropertyManager())
    }
    callback(null, this.properties.get(pathStr))
  }

  _type(path, ctx, callback) {
    const pathStr = path.toString()

    if (pathStr === '/') {
      return callback(null, webdav.ResourceType.Directory)
    }

    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (file) {
      return callback(null, webdav.ResourceType.File)
    }


    const files = listFiles(this.vault.id, keyPath)
    if (files.length > 0) {
      return callback(null, webdav.ResourceType.Directory)
    }

    callback(webdav.Errors.ResourceNotFound)
  }

  _readDir(path, ctx, callback) {
    const pathStr = path.toString()
    const prefix = pathStr === '/' ? '' : (pathStr.startsWith('/') ? pathStr.slice(1) + '/' : pathStr + '/')

    const files = listFiles(this.vault.id, prefix || null)
    const entries = new Set()

    for (const file of files) {
      let relativePath = file.path
      if (prefix) {
        if (!relativePath.startsWith(prefix)) continue
        relativePath = relativePath.slice(prefix.length)
      }

      const parts = relativePath.split('/')
      if (parts[0]) {
        entries.add(parts[0])
      }
    }

    callback(null, Array.from(entries))
  }

  _size(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (!file) {
      return callback(webdav.Errors.ResourceNotFound)
    }

    callback(null, file.size)
  }

  _openReadStream(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (!file) {
      return callback(webdav.Errors.ResourceNotFound)
    }

    const fileKey = deriveFileKey(this.vaultKey, file.id)
    const chunks = getChunksByFileId(file.id)

    const { Readable } = require('stream')
    const self = this


    const chunkIds = chunks.map(c => c.id)

    const readable = new Readable({
      read() { }
    })


      ; (async () => {
        try {

          const encryptedChunks = await downloadChunksParallel(chunkIds, 12)


          let totalPushed = 0
          for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i]
            const nonce = new Uint8Array(chunk.nonce)
            const decrypted = decryptChunk(encryptedChunks[i], nonce, fileKey, chunk.chunkIndex)


            let data = Buffer.from(decrypted)
            if (totalPushed + data.length > file.size) {
              data = data.slice(0, file.size - totalPushed)
            }
            totalPushed += data.length
            readable.push(data)
          }
          readable.push(null)
        } catch (err) {
          readable.destroy(err)
        }
      })()

    callback(null, readable)
  }

  _openWriteStream(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const self = this

    const { Writable } = require('stream')
    const chunks = []

    const writable = new Writable({
      write(chunk, encoding, cb) {
        chunks.push(chunk)
        cb()
      },
      async final(cb) {
        try {
          const fileData = Buffer.concat(chunks)
          const existingFile = getFileByPath(self.vault.id, keyPath)

          if (existingFile) {
            const oldChunks = getChunksByFileId(existingFile.id)
            for (const chunk of oldChunks) {
              await deleteChunk(chunk.id)
            }
            deleteFileFromCache(existingFile.id)
          }

          const fileId = generateId()
          const fileKey = deriveFileKey(self.vaultKey, fileId)
          const now = new Date().toISOString()

          const fileChunks = chunkFile(fileData)

          const file = {
            id: fileId,
            vaultId: self.vault.id,
            path: keyPath,
            size: fileData.length,
            mime: null,
            hash: null,
            createdAt: now,
            updatedAt: now
          }

          addFileToDb(file)

          const encryptedChunks = fileChunks.map((chunk, i) => {
            const { encrypted, nonce } = encryptChunk(chunk, fileKey, i)
            return { encrypted, nonce, index: i }
          })

          const uploadResults = await uploadChunksParallel(
            encryptedChunks.map(c => c.encrypted),
            12
          )

          const chunkRecords = []
          for (let i = 0; i < encryptedChunks.length; i++) {
            const chunkRecord = {
              id: uploadResults[i].id,
              chunkIndex: i,
              nonce: sodium.to_base64(encryptedChunks[i].nonce),
              size: encryptedChunks[i].encrypted.length
            }
            chunkRecords.push(chunkRecord)
            addChunk({
              id: uploadResults[i].id,
              fileId,
              chunkIndex: i,
              nonce: Buffer.from(encryptedChunks[i].nonce),
              size: encryptedChunks[i].encrypted.length
            })
          }

          addPendingOp({
            type: 'create_file',
            timestamp: Date.now(),
            deviceId: getDeviceId(),
            file,
            chunks: chunkRecords
          })

          cb()
        } catch (err) {
          cb(err)
        }
      }
    })

    callback(null, writable)
  }

  _create(path, ctx, callback) {
    if (ctx.type.isDirectory) {

      callback(null)
    } else {

      callback(null)
    }
  }

  _delete(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (!file) {
      return callback(webdav.Errors.ResourceNotFound)
    }

    const self = this

      ; (async () => {
        try {
          const chunks = getChunksByFileId(file.id)
          for (const chunk of chunks) {
            await deleteChunk(chunk.id)
          }
          deleteFileFromCache(file.id)
          addPendingOp({
            type: 'delete_file',
            timestamp: Date.now(),
            deviceId: getDeviceId(),
            fileId: file.id
          })
          callback(null)
        } catch (err) {
          callback(err)
        }
      })()
  }

  _creationDate(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (file) {
      callback(null, new Date(file.createdAt).getTime())
    } else {
      callback(null, Date.now())
    }
  }

  _lastModifiedDate(path, ctx, callback) {
    const pathStr = path.toString()
    const keyPath = pathStr.startsWith('/') ? pathStr.slice(1) : pathStr
    const file = getFileByPath(this.vault.id, keyPath)

    if (file) {
      callback(null, new Date(file.updatedAt).getTime())
    } else {
      callback(null, Date.now())
    }
  }
}

const serveCmd = program.command('serve').description('Serve files via different protocols')

serveCmd
  .command('webdav')
  .description('Start a WebDAV server to access encrypted files')
  .option('-p, --port <port>', 'Port to listen on', '1900')
  .option('-h, --host <host>', 'Host to bind to', '127.0.0.1')
  .option('-v, --vault <name>', 'Specific vault to serve (optional, serves all if not specified)')
  .action(async (options) => {
    try {
      const config = await getConfig()
      if (!config?.kek) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      await syncOps(config.kek, false)

      const dataKey = getDataKey(config.kek)
      const port = parseInt(options.port)
      const host = options.host

      const server = new webdav.WebDAVServer({
        port,
        hostname: host
      })

      if (options.vault) {
        const vault = getVaultByName(options.vault)
        if (!vault) {
          console.error(`Vault "${options.vault}" not found`)
          process.exit(1)
        }

        const vaultFs = new EncryptedVaultFileSystem(vault, dataKey)
        server.setFileSystem('/', vaultFs, (success) => {
          if (!success) {
            console.error('Failed to mount vault')
            process.exit(1)
          }
        })

        console.log(`Mounting vault: ${vault.name}`)
      } else {
        const vaults = listVaults()
        if (vaults.length === 0) {
          console.error('No vaults found. Create one with: catboy vault create <name>')
          process.exit(1)
        }

        for (const vault of vaults) {
          const vaultFs = new EncryptedVaultFileSystem(vault, dataKey)
          server.setFileSystem(`/${vault.name}`, vaultFs, (success) => {
            if (!success) {
              console.error(`Failed to mount vault: ${vault.name}`)
            }
          })
          console.log(`Mounting vault: ${vault.name} at /${vault.name}`)
        }
      }

      server.start(() => {
        console.log(`\nWebDAV server running at http://${host}:${port}`)
        console.log('\nConnect using:')
        console.log(`  - macOS Finder: Go > Connect to Server > http://${host}:${port}`)
        console.log(`  - Windows: Map network drive > \\\\${host}@${port}\\DavWWWRoot`)
        console.log(`  - Linux: davfs2 or mount.davfs http://${host}:${port}`)
        console.log('\nPress Ctrl+C to stop the server.')
      })

      const SYNC_INTERVAL = 60 * 1000
      const syncTimer = setInterval(async () => {
        try {
          await syncOps(config.kek, true)
        } catch (err) {
          console.error('Background sync failed:', err.message)
        }
      }, SYNC_INTERVAL)

      process.on('SIGINT', async () => {
        clearInterval(syncTimer)
        console.log('\nSyncing before shutdown...')
        await syncOps(config.kek, true)
        console.log('Goodbye!')
        process.exit(0)
      })

      await new Promise(() => { })

    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('export')
  .description('Export account credentials to a file for use on another device')
  .argument('<file>', 'Output file path')
  .action(async (filePath) => {
    try {
      const config = await getConfig()
      if (!config) {
        console.error('Not logged in. Run `catboy register` or `catboy login` first.')
        process.exit(1)
      }

      const password = await promptPassword('Enter your password to verify: ')
      const salt = sodium.from_base64(config.salt)
      const { masterKey } = createMasterKeyFromPassword(password, salt)
      const kek = createKeyEncryptionKey(masterKey)

      if (sodium.to_base64(kek) !== config.kek) {
        console.error('Incorrect password')
        process.exit(1)
      }

      const encryptedDataKey = getEncryptedDataKey()
      if (!encryptedDataKey) {
        console.error('No data key found')
        process.exit(1)
      }

      const exportData = {
        version: 1,
        accountNumber: config.accountNumber,
        salt: config.salt,
        encryptedDataKey
      }

      const outputPath = path.resolve(filePath)
      fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2))
      console.log(`Credentials exported to: ${outputPath}`)
      console.log('\nThis file contains your encrypted credentials.')
      console.log('You will need your password to import on another device.')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program
  .command('import')
  .description('Import account credentials from an export file')
  .argument('<file>', 'Input file path')
  .action(async (filePath) => {
    try {
      const existing = await getConfig()
      if (existing?.accountNumber) {
        console.error('Already logged in. Run `catboy logout` first.')
        process.exit(1)
      }

      const inputPath = path.resolve(filePath)
      if (!fs.existsSync(inputPath)) {
        console.error(`File not found: ${inputPath}`)
        process.exit(1)
      }

      const importData = JSON.parse(fs.readFileSync(inputPath, 'utf8'))
      if (importData.version !== 1) {
        console.error('Unsupported export file version')
        process.exit(1)
      }

      const password = await promptPassword('Enter your password: ')
      const salt = sodium.from_base64(importData.salt)

      console.log('Deriving encryption keys (this may take a moment)...')
      const { masterKey } = createMasterKeyFromPassword(password, salt)
      const kek = createKeyEncryptionKey(masterKey)

      try {
        const encryptedDataKey = sodium.from_base64(importData.encryptedDataKey)
        decryptDataKey(encryptedDataKey, kek)
      } catch (e) {
        console.error('Incorrect password or corrupted export file')
        process.exit(1)
      }

      const result = await login(importData.accountNumber)

      await saveConfig({
        accountNumber: importData.accountNumber,
        token: result.token,
        salt: importData.salt,
        kek: sodium.to_base64(kek)
      })

      resetDatabase()
      setEncryptedDataKey(importData.encryptedDataKey)
      await syncOps(sodium.to_base64(kek), false)

      console.log('Account imported successfully!')
    } catch (err) {
      console.error('Error:', err.message)
      process.exit(1)
    }
  })

program.parse()
