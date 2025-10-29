// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- file paths
const CHAIN_FILE = path.join(__dirname, 'data', 'chain.json');

// --- helper: read/write chain
function readChain() {
  try {
    const raw = fs.readFileSync(CHAIN_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return [];
  }
}
function writeChain(chain) {
  fs.writeFileSync(CHAIN_FILE, JSON.stringify(chain, null, 2));
}

// --- hashing
function calculateHash(index, timestamp, certificateHash, previousHash) {
  const str = index + timestamp + certificateHash + previousHash;
  return crypto.createHash('sha256').update(str).digest('hex');
}

// --- certificate hash (content hashing)
function makeCertificateHash({ certId, studentName, issuer, issueDate }) {
  const s = `${certId}|${studentName}|${issuer}|${issueDate}`;
  return crypto.createHash('sha256').update(s).digest('hex');
}

// --- create genesis block if none
function ensureChain() {
  let chain = readChain();
  if (!chain || chain.length === 0) {
    const timestamp = new Date().toISOString();
    const genesisCert = {
      certId: 'GENESIS-0',
      studentName: 'GENESIS',
      issuer: 'GENESIS',
      issueDate: timestamp
    };
    const certificateHash = makeCertificateHash(genesisCert);
    const genesis = {
      index: 0,
      timestamp,
      certificateHash,
      certId: genesisCert.certId,
      studentName: genesisCert.studentName,
      issuer: genesisCert.issuer,
      issueDate: genesisCert.issueDate,
      previousHash: '0',
      hash: calculateHash(0, timestamp, certificateHash, '0')
    };
    chain = [genesis];
    writeChain(chain);
    return chain;
  }
  return chain;
}

// --- utility: get latest block
function getLatestBlock(chain) {
  return chain[chain.length - 1];
}

// --- validate chain integrity
function isChainValid(chain) {
  for (let i = 1; i < chain.length; i++) {
    const current = chain[i];
    const prev = chain[i - 1];
    const checkHash = calculateHash(current.index, current.timestamp, current.certificateHash, current.previousHash);
    if (current.hash !== checkHash) return false;
    if (current.previousHash !== prev.hash) return false;
  }
  return true;
}

// Initialize chain on server start
let chain = ensureChain();

// --- endpoint: view chain
app.get('/chain', (req, res) => {
  chain = readChain();
  return res.json({ length: chain.length, valid: isChainValid(chain), chain });
});

// --- endpoint: add certificate (admin)
app.post('/addCertificate', (req, res) => {
  /*
    Expected JSON body:
    {
      "certId": "CERT-123",
      "studentName": "Md. X",
      "issuer": "Holy Land School",
      "issueDate": "2025-11-06"
    }
  */
  const { certId, studentName, issuer, issueDate } = req.body;
  if (!certId || !studentName || !issuer || !issueDate) {
    return res.status(400).json({ ok: false, error: 'certId, studentName, issuer, issueDate are required' });
  }

  chain = readChain();
  const idx = chain.length;
  const timestamp = new Date().toISOString();

  const certificateHash = makeCertificateHash({ certId, studentName, issuer, issueDate });
  const previousHash = getLatestBlock(chain).hash;
  const hash = calculateHash(idx, timestamp, certificateHash, previousHash);

  const newBlock = {
    index: idx,
    timestamp,
    certificateHash,
    certId,
    studentName,
    issuer,
    issueDate,
    previousHash,
    hash
  };

  chain.push(newBlock);
  writeChain(chain);

  return res.json({ ok: true, block: newBlock });
});

// --- endpoint: verify certificate by certId
app.get('/verify/:certId', (req, res) => {
  const { certId } = req.params;
  chain = readChain();

  // find block(s) matching certId
  const matches = chain.filter(b => b.certId === certId);
  if (matches.length === 0) {
    return res.json({ ok: false, message: 'Certificate not found' });
  }

  // For each match, verify integrity (recompute hash & chain validity)
  const results = matches.map(block => {
    const recomputedCertificateHash = makeCertificateHash({
      certId: block.certId,
      studentName: block.studentName,
      issuer: block.issuer,
      issueDate: block.issueDate
    });
    const recomputedHash = calculateHash(block.index, block.timestamp, recomputedCertificateHash, block.previousHash);
    const intact = recomputedHash === block.hash;
    return {
      block,
      intact
    };
  });

  // Also overall chain validity
  const overallValid = isChainValid(chain);

  return res.json({ ok: true, overallChainValid: overallValid, results });
});

// --- endpoint: simple AI chatbot
app.post('/chat', (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ ok: false, error: 'message is required' });

  const msg = message.toLowerCase().trim();

  // If user asks to verify with example "verify CERT-123" or "is CERT-123 valid?"
  const verifyMatch = msg.match(/(verify|is|check).*(cert[-\s]?\w+)/i) || msg.match(/(cert[-\s]?\w+)/i);
  if (verifyMatch) {
    // get cert id token from message
    const possible = verifyMatch[2] || verifyMatch[1];
    const certId = (possible || '').toUpperCase().replace(/\s+/g, '');
    if (certId) {
      // call verification logic
      const chainNow = readChain();
      const matches = chainNow.filter(b => b.certId.toUpperCase() === certId);
      if (matches.length === 0) {
        return res.json({ ok: true, reply: `I couldn't find certificate ID ${certId}. Please check the ID and try again.` });
      } else {
        const block = matches[0];
        const recomputedCertificateHash = makeCertificateHash({
          certId: block.certId,
          studentName: block.studentName,
          issuer: block.issuer,
          issueDate: block.issueDate
        });
        const recomputedHash = calculateHash(block.index, block.timestamp, recomputedCertificateHash, block.previousHash);
        const intact = recomputedHash === block.hash;
        const reply = intact
          ? `✅ Certificate ${block.certId} is valid. Issued to ${block.studentName} by ${block.issuer} on ${block.issueDate}.`
          : `❌ Certificate ${block.certId} appears tampered or invalid.`;
        return res.json({ ok: true, reply, block });
      }
    }
  }

  // Simple rule-based answers
  if (msg.includes('how') && msg.includes('verify')) {
    return res.json({ ok: true, reply: 'Go to Verify section and enter the certificate ID (e.g., CERT-123). Or ask me "verify CERT-123".' });
  } else if (msg.includes('what') && msg.includes('blockchain')) {
    return res.json({ ok: true, reply: 'Blockchain is a tamper-evident distributed ledger. In this project, each certificate is stored as a block containing a hash.' });
  } else if (msg.includes('hello') || msg.includes('hi')) {
    return res.json({ ok: true, reply: 'Hi! I can help verify certificates. Try: "verify CERT-123" or ask how verification works.' });
  } else {
    return res.json({ ok: true, reply: "Sorry, I didn't get that. Ask me to 'verify CERT-xxx' or 'how to verify'." });
  }
});

// --- serve static frontend
app.use('/', express.static(path.join(__dirname, 'public')));

// --- start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
