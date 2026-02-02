import { getConfig } from './db.js'

const API_URL = process.env.CATBOYS_API_URL || 'https://catboys.nu'

export async function createAccount() {
  const res = await fetch(`${API_URL}/account/create`, { method: 'POST' })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function login(accountNumber) {
  const res = await fetch(`${API_URL}/account/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountNumber })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function logout() {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/account/logout`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getAccountInfo() {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/account/info`, {
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function uploadChunk(chunkData) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const formData = new FormData()
  formData.append('chunk', new Blob([chunkData]))

  const res = await fetch(`${API_URL}/chunks/upload`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${config.token}` },
    body: formData
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function downloadChunk(chunkId) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks/${chunkId}`, {
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return new Uint8Array(await res.arrayBuffer())
}


export async function getPresignedDownloadUrls(chunkIds) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks/presign/download`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ chunkIds })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}


export async function getPresignedUploadUrls(count, size = 0) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks/presign/upload`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ count, size })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}


export async function updateChunkSize(chunkId, size) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks/${chunkId}`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${config.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ size })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}


export async function downloadChunksParallel(chunkIds, concurrency = 10) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')


  const { urls } = await getPresignedDownloadUrls(chunkIds)

  const results = new Array(chunkIds.length)
  let index = 0

  async function worker() {
    while (index < chunkIds.length) {
      const i = index++
      const url = urls[chunkIds[i]]
      if (!url) throw new Error(`No presigned URL for chunk ${chunkIds[i]}`)


      const res = await fetch(url)
      if (!res.ok) throw new Error(`S3 download failed: ${res.status}`)
      results[i] = new Uint8Array(await res.arrayBuffer())
    }
  }

  await Promise.all(Array(Math.min(concurrency, chunkIds.length)).fill(null).map(() => worker()))
  return results
}


export async function uploadChunksParallel(encryptedChunks, concurrency = 10) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')


  const { chunks: presignedChunks } = await getPresignedUploadUrls(encryptedChunks.length)

  const results = new Array(encryptedChunks.length)
  let index = 0

  async function worker() {
    while (index < encryptedChunks.length) {
      const i = index++
      const { id, url } = presignedChunks[i]
      const data = encryptedChunks[i]


      const res = await fetch(url, {
        method: 'PUT',
        body: data,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': data.length.toString()
        }
      })
      if (!res.ok) throw new Error(`S3 upload failed: ${res.status}`)


      await updateChunkSize(id, data.length)

      results[i] = { id, size: data.length.toString() }
    }
  }

  await Promise.all(Array(Math.min(concurrency, encryptedChunks.length)).fill(null).map(() => worker()))
  return results
}

export async function deleteChunk(chunkId) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks/${chunkId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function listChunks() {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/chunks`, {
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getIndexVersion() {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/index/version`, {
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function getOps(since = 0) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/ops?since=${since}`, {
    headers: { 'Authorization': `Bearer ${config.token}` }
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function pushOps(ops) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/ops`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ ops })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export async function compactOps(snapshotOp, upToVersion) {
  const config = await getConfig()
  if (!config?.token) throw new Error('Not logged in')

  const res = await fetch(`${API_URL}/ops/compact`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ snapshotOp, upToVersion })
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}
