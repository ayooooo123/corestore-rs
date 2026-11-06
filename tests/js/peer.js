// npm corestore side of tests/interop.rs.
//
// node peer.js keys <dir>
//   prints JSON: keys derived from a fixed primary key in several namespaces.
// node peer.js read <dir> <port> <key-hex>...
//   connects over secret-stream, downloads every listed core, prints
//   "core <key> <length> <sha256>" per core, then exits.
// node peer.js write <dir> <name>
//   writes 50 blocks to a named core, prints "key <hex>" and "port <n>", seeds.
const net = require('net')
const fs = require('fs')
const crypto = require('crypto')
const Corestore = require('corestore')
const SecretStream = require('@hyperswarm/secret-stream')

const log = (s) => process.stdout.write(s + '\n')
const [mode, dir, ...args] = process.argv.slice(2)
fs.rmSync(dir, { recursive: true, force: true })

async function keys() {
  const store = new Corestore(dir, { primaryKey: Buffer.alloc(32, 7), unsafe: true })
  await store.ready()
  const out = []
  const views = [
    ['', store],
    ['a', store.namespace('a')],
    ['a/b', store.namespace('a').namespace('b')],
    ['bytes', store.namespace(Buffer.from([0, 1, 2, 255]))]
  ]
  for (const [path, view] of views) {
    for (const name of ['main', 'video-blobs', 'ü']) {
      const core = view.get({ name })
      await core.ready()
      const kp = await view.createKeyPair(name)
      out.push({ path, name, publicKey: kp.publicKey.toString('hex'), key: core.key.toString('hex'), discoveryKey: core.discoveryKey.toString('hex') })
      await core.close()
    }
  }
  await store.close()
  log(JSON.stringify(out))
}

async function read() {
  const [port, ...keys] = args
  const store = new Corestore(dir)
  const ss = new SecretStream(true, net.connect(Number(port), '127.0.0.1'))
  ss.on('error', () => {})
  store.replicate(ss)
  for (const key of keys) {
    const core = store.get({ key: Buffer.from(key, 'hex') })
    await core.ready()
    await core.update({ wait: true })
    const hash = crypto.createHash('sha256')
    for (let i = 0; i < core.length; i++) hash.update(await core.get(i))
    log('core ' + key + ' ' + core.length + ' ' + hash.digest('hex'))
  }
  ss.destroy()
  await store.close()
  process.exit(0)
}

async function write() {
  const [name] = args
  const store = new Corestore(dir)
  const core = store.get({ name })
  await core.ready()
  for (let i = 0; i < 50; i++) await core.append(Buffer.from('js-block-' + i))
  log('key ' + core.key.toString('hex'))
  const server = net.createServer((socket) => {
    const ss = new SecretStream(false, socket)
    store.replicate(ss)
    ss.on('error', () => {})
    ss.on('close', async () => {
      await store.close()
      process.exit(0)
    })
  })
  server.listen(0, '127.0.0.1', () => log('port ' + server.address().port))
}

;({ keys, read, write })[mode]().catch((err) => {
  log('error ' + err.stack)
  process.exit(1)
})
