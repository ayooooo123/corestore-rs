// npm corestore side of tests/interop.rs, over Hyperswarm on a local HyperDHT testnet (UDX).
//
// node peer.js keys <dir>
//   prints JSON: keys derived from a fixed primary key in several namespaces.
// node peer.js testnet
//   runs a 3-node testnet, prints "bootstrap <port>"; exits when stdin closes.
// node peer.js read <dir> <bootstrap-port> <topic-hex> <key-hex>...
//   joins the topic as a client, downloads every listed core, prints
//   "core <key> <length> <sha256>" per core, then exits.
// node peer.js write <dir> <bootstrap-port> <topic-hex> <name>
//   writes 50 blocks to a named core, prints "key <hex>", announces the topic, prints "ready".
const fs = require('fs')
const crypto = require('crypto')
const Corestore = require('corestore')
const Hyperswarm = require('hyperswarm')
const createTestnet = require('hyperdht/testnet')

const log = (s) => process.stdout.write(s + '\n')
const [mode, ...args] = process.argv.slice(2)
process.stdin.on('end', () => process.exit(0))
process.stdin.resume()

function swarm(port) {
  return new Hyperswarm({ bootstrap: [{ host: '127.0.0.1', port: Number(port) }] })
}

async function testnet() {
  const t = await createTestnet(3, { host: '127.0.0.1' })
  log('bootstrap ' + t.bootstrap[0].port)
}

async function keys() {
  const [dir] = args
  fs.rmSync(dir, { recursive: true, force: true })
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
  process.exit(0)
}

async function read() {
  const [dir, port, topic, ...keys] = args
  fs.rmSync(dir, { recursive: true, force: true })
  const store = new Corestore(dir)
  const s = swarm(port)
  s.on('connection', (conn) => store.replicate(conn))
  s.join(Buffer.from(topic, 'hex'), { server: false, client: true })
  for (const key of keys) {
    const core = store.get({ key: Buffer.from(key, 'hex') })
    await core.ready()
    while (core.length === 0) {
      await core.update({ wait: true })
      if (core.length === 0) await new Promise((resolve) => setTimeout(resolve, 200))
    }
    const hash = crypto.createHash('sha256')
    for (let i = 0; i < core.length; i++) hash.update(await core.get(i))
    log('core ' + key + ' ' + core.length + ' ' + hash.digest('hex'))
  }
  await s.destroy()
  await store.close()
  process.exit(0)
}

async function write() {
  const [dir, port, topic, name] = args
  fs.rmSync(dir, { recursive: true, force: true })
  const store = new Corestore(dir)
  const core = store.get({ name })
  await core.ready()
  for (let i = 0; i < 50; i++) await core.append(Buffer.from('js-block-' + i))
  log('key ' + core.key.toString('hex'))
  const s = swarm(port)
  s.on('connection', (conn) => store.replicate(conn))
  await s.join(Buffer.from(topic, 'hex'), { server: true, client: false }).flushed()
  log('ready')
}

;({ keys, testnet, read, write })[mode]().catch((err) => {
  log('error ' + err.stack)
  process.exit(1)
})
