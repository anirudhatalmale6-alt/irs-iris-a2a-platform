const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, '..', 'data', 'submissions.json');

function ensureDir() {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readAll() {
  ensureDir();
  if (!fs.existsSync(DB_FILE)) return [];
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeAll(data) {
  ensureDir();
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function addSubmission(submission) {
  const all = readAll();
  submission.createdAt = new Date().toISOString();
  all.push(submission);
  writeAll(all);
  return submission;
}

function updateSubmission(id, updates) {
  const all = readAll();
  const idx = all.findIndex(s => s.id === id);
  if (idx === -1) return null;
  Object.assign(all[idx], updates, { updatedAt: new Date().toISOString() });
  writeAll(all);
  return all[idx];
}

function getSubmission(id) {
  return readAll().find(s => s.id === id) || null;
}

function getPayouts() {
  const payoutsFile = path.join(path.dirname(DB_FILE), 'payouts.json');
  if (!fs.existsSync(payoutsFile)) return [];
  return JSON.parse(fs.readFileSync(payoutsFile, 'utf8'));
}

function addPayout(payout) {
  const payoutsFile = path.join(path.dirname(DB_FILE), 'payouts.json');
  ensureDir();
  const all = fs.existsSync(payoutsFile) ? JSON.parse(fs.readFileSync(payoutsFile, 'utf8')) : [];
  payout.createdAt = new Date().toISOString();
  all.push(payout);
  fs.writeFileSync(payoutsFile, JSON.stringify(all, null, 2));
  return payout;
}

module.exports = { readAll, addSubmission, updateSubmission, getSubmission, getPayouts, addPayout };
