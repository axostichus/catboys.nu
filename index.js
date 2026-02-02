import { Hono } from 'hono'
import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'
import pg from 'pg'
import crypto from 'crypto'
import { S3Client } from 'bun'
import { Liquid } from 'liquidjs'
import fs from 'fs'
import { serveStatic } from '@hono/node-server/serve-static'

const engine = new Liquid({
  root: './views',
  extname: '.liquid',
  globals: {
    css: fs.readFileSync("./public/style.css")
  }
})

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const adapter = new PrismaPg(pool)
const prisma = new PrismaClient({ adapter })

const s3 = new S3Client({
  accessKeyId: process.env.S3_KEY_ID,
  secretAccessKey: process.env.S3_KEY_SECRET,
  bucket: process.env.S3_BUCKET,
  endpoint: process.env.S3_ENDPOINT,
})

const app = new Hono()

function generateAccountNumber() {
  return crypto.randomBytes(8).toString('hex').toUpperCase()
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex')
}

async function authenticateRequest(c, next) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid authorization header' }, 401)
  }

  const token = authHeader.slice(7)
  const apiToken = await prisma.apiToken.findUnique({
    where: { token },
    include: { user: true }
  })

  if (!apiToken || !apiToken.user.active) {
    return c.json({ error: 'Invalid or expired token' }, 401)
  }

  c.set('user', apiToken.user)
  c.set('apiToken', apiToken)
  await next()
}

app.get('/', async (c) => {
  const html = await engine.renderFile('home')
  return c.html(html)
})

app.get('/architecture', async (c) => {
  const html = await engine.renderFile('architecture')
  return c.html(html)
})

app.post('/account/create', async (c) => {
  const accountNumber = generateAccountNumber()
  const token = generateToken()

  const user = await prisma.user.create({
    data: {
      accountNumber,
      apiTokens: {
        create: { token }
      }
    }
  })

  return c.json({
    accountNumber: user.accountNumber,
    token
  })
})

app.post('/account/login', async (c) => {
  const { accountNumber } = await c.req.json()

  if (!accountNumber) {
    return c.json({ error: 'Account number required' }, 400)
  }

  const user = await prisma.user.findUnique({
    where: { accountNumber }
  })

  if (!user || !user.active) {
    return c.json({ error: 'Account not found or inactive' }, 404)
  }

  const token = generateToken()
  await prisma.apiToken.create({
    data: {
      token,
      userId: user.id
    }
  })

  return c.json({ token })
})

app.post('/account/logout', authenticateRequest, async (c) => {
  const apiToken = c.get('apiToken')
  await prisma.apiToken.delete({ where: { id: apiToken.id } })
  return c.json({ success: true })
})

app.get('/account/info', authenticateRequest, async (c) => {
  const user = c.get('user')
  const chunks = await prisma.chunk.findMany({
    where: { userId: user.id },
    select: { size: true }
  })

  const totalSize = chunks.reduce((sum, chunk) => sum + chunk.size, 0n)

  return c.json({
    accountNumber: user.accountNumber,
    createdAt: user.createdAt,
    chunkCount: chunks.length,
    totalSize: totalSize.toString()
  })
})

app.post('/chunks/upload', authenticateRequest, async (c) => {
  const user = c.get('user')
  const body = await c.req.parseBody()
  const file = body['chunk']

  if (!file || typeof file === 'string') {
    return c.json({ error: 'No chunk data provided' }, 400)
  }

  const chunkData = Buffer.from(await file.arrayBuffer())

  const chunk = await prisma.chunk.create({
    data: {
      size: BigInt(chunkData.length),
      userId: user.id
    }
  })

  await s3.write(`chunks/${chunk.id}`, chunkData)

  return c.json({
    id: chunk.id,
    size: chunk.size.toString()
  })
})

app.get('/chunks/:id', authenticateRequest, async (c) => {
  const user = c.get('user')
  const chunkId = c.req.param('id')

  const chunk = await prisma.chunk.findUnique({
    where: { id: chunkId }
  })

  if (!chunk || chunk.userId !== user.id) {
    return c.json({ error: 'Chunk not found' }, 404)
  }

  const s3File = s3.file(`chunks/${chunk.id}`)
  const chunkData = await s3File.arrayBuffer()

  return new Response(chunkData, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': chunk.size.toString()
    }
  })
})


app.get('/chunks/:id/presign', authenticateRequest, async (c) => {
  const user = c.get('user')
  const chunkId = c.req.param('id')

  const chunk = await prisma.chunk.findUnique({
    where: { id: chunkId }
  })

  if (!chunk || chunk.userId !== user.id) {
    return c.json({ error: 'Chunk not found' }, 404)
  }

  const url = s3.presign(`chunks/${chunk.id}`, {
    expiresIn: 3600,
    method: 'GET'
  })

  return c.json({ url })
})


app.post('/chunks/presign/download', authenticateRequest, async (c) => {
  const user = c.get('user')
  const { chunkIds } = await c.req.json()

  if (!Array.isArray(chunkIds) || chunkIds.length === 0) {
    return c.json({ error: 'chunkIds array required' }, 400)
  }

  const chunks = await prisma.chunk.findMany({
    where: {
      id: { in: chunkIds },
      userId: user.id
    }
  })

  const chunkMap = new Map(chunks.map(c => [c.id, c]))
  const urls = {}

  for (const id of chunkIds) {
    if (chunkMap.has(id)) {
      urls[id] = s3.presign(`chunks/${id}`, {
        expiresIn: 3600,
        method: 'GET'
      })
    }
  }

  return c.json({ urls })
})


app.post('/chunks/presign/upload', authenticateRequest, async (c) => {
  const user = c.get('user')
  const { size, count = 1 } = await c.req.json()

  const results = []

  for (let i = 0; i < count; i++) {
    const chunk = await prisma.chunk.create({
      data: {
        size: BigInt(size || 0),
        userId: user.id
      }
    })

    const url = s3.presign(`chunks/${chunk.id}`, {
      expiresIn: 3600,
      method: 'PUT'
    })

    results.push({
      id: chunk.id,
      url
    })
  }

  return c.json({ chunks: results })
})


app.patch('/chunks/:id', authenticateRequest, async (c) => {
  const user = c.get('user')
  const chunkId = c.req.param('id')
  const { size } = await c.req.json()

  const chunk = await prisma.chunk.findUnique({
    where: { id: chunkId }
  })

  if (!chunk || chunk.userId !== user.id) {
    return c.json({ error: 'Chunk not found' }, 404)
  }

  await prisma.chunk.update({
    where: { id: chunkId },
    data: { size: BigInt(size) }
  })

  return c.json({ success: true })
})

app.delete('/chunks/:id', authenticateRequest, async (c) => {
  const user = c.get('user')
  const chunkId = c.req.param('id')

  const chunk = await prisma.chunk.findUnique({
    where: { id: chunkId }
  })

  if (!chunk || chunk.userId !== user.id) {
    return c.json({ error: 'Chunk not found' }, 404)
  }

  await s3.delete(`chunks/${chunk.id}`)
  await prisma.chunk.delete({ where: { id: chunkId } })

  return c.json({ success: true })
})

app.get('/chunks', authenticateRequest, async (c) => {
  const user = c.get('user')

  const chunks = await prisma.chunk.findMany({
    where: { userId: user.id },
    select: {
      id: true,
      size: true,
      createdAt: true
    },
    orderBy: { createdAt: 'desc' }
  })

  return c.json({
    chunks: chunks.map(chunk => ({
      id: chunk.id,
      size: chunk.size.toString(),
      createdAt: chunk.createdAt
    }))
  })
})

app.get('/index/version', authenticateRequest, async (c) => {
  const user = c.get('user')
  const meta = await prisma.opLogMeta.findUnique({
    where: { userId: user.id }
  })

  return c.json({
    version: meta?.latestVersion || 0,
    compactedUpTo: meta?.compactedUpTo || 0,
    updatedAt: meta?.updatedAt || null
  })
})

app.get('/ops', authenticateRequest, async (c) => {
  const user = c.get('user')
  const since = parseInt(c.req.query('since') || '0')

  const ops = await prisma.opLog.findMany({
    where: {
      userId: user.id,
      version: { gt: since }
    },
    orderBy: { version: 'asc' },
    select: {
      version: true,
      data: true
    }
  })

  const meta = await prisma.opLogMeta.findUnique({
    where: { userId: user.id }
  })

  return c.json({
    ops: ops.map(op => ({
      version: op.version,
      data: Buffer.from(op.data).toString('base64')
    })),
    latestVersion: meta?.latestVersion || 0,
    compactedUpTo: meta?.compactedUpTo || 0
  })
})

app.post('/ops', authenticateRequest, async (c) => {
  const user = c.get('user')
  const { ops } = await c.req.json()

  if (!Array.isArray(ops) || ops.length === 0) {
    return c.json({ error: 'ops array required' }, 400)
  }

  const meta = await prisma.opLogMeta.upsert({
    where: { userId: user.id },
    update: {},
    create: { userId: user.id, latestVersion: 0, compactedUpTo: 0 }
  })

  let nextVersion = meta.latestVersion + 1
  const createdOps = []

  for (const op of ops) {
    const data = Buffer.from(op.data, 'base64')
    const created = await prisma.opLog.create({
      data: {
        userId: user.id,
        version: nextVersion,
        data
      }
    })
    createdOps.push({ version: created.version })
    nextVersion++
  }

  await prisma.opLogMeta.update({
    where: { userId: user.id },
    data: { latestVersion: nextVersion - 1 }
  })

  return c.json({
    created: createdOps,
    latestVersion: nextVersion - 1
  })
})

app.post('/ops/compact', authenticateRequest, async (c) => {
  const user = c.get('user')
  const { snapshotOp, upToVersion } = await c.req.json()

  if (!snapshotOp || !upToVersion) {
    return c.json({ error: 'snapshotOp and upToVersion required' }, 400)
  }

  const meta = await prisma.opLogMeta.findUnique({
    where: { userId: user.id }
  })

  if (!meta || upToVersion > meta.latestVersion) {
    return c.json({ error: 'Invalid upToVersion' }, 400)
  }

  await prisma.$transaction(async (tx) => {
    await tx.opLog.deleteMany({
      where: {
        userId: user.id,
        version: { lte: upToVersion }
      }
    })

    const data = Buffer.from(snapshotOp.data, 'base64')
    await tx.opLog.create({
      data: {
        userId: user.id,
        version: 0,
        data
      }
    })

    await tx.opLogMeta.update({
      where: { userId: user.id },
      data: { compactedUpTo: upToVersion }
    })
  })

  return c.json({
    success: true,
    compactedUpTo: upToVersion
  })
})

app.use('/*', serveStatic({ root: './public' }))

export default app
