#!/usr/bin/env node
// Helio environment fan-out plan step (design sections 6.2, 8 and 9.4; reviews
// d94d19d and e545cee).
//
// Reads the dispatcher's requested instance subset from the environment (never
// from shell arguments), verifies the committed manifest's Ed25519 signature and
// the committed activation attestation with the committed public key, checks
// that this workflow's deploy job set equals the manifest's instance set, and
// publishes the SELECTED instance names to $GITHUB_OUTPUT. Every deploy job is
// gated on that selection, so a subset can only narrow the deployment.
//
// Two fail-closed modes, chosen by HELIO_MODE (set literally by the generated
// workflow, never by an input):
//   forward  (default) the build-and-deploy entry workflow. A selection must be
//            closed under earlier tiers: choosing any instance of a tier
//            requires every instance of all earlier tiers.
//   redeploy the deployment-only entry workflow. Exactly one known instance is
//            selected, earlier tiers are not required, the workflow must be the
//            manifest's signed redeploy entry, and the artifact inputs must be
//            immutable (digest-pinned URI).
// Any failure exits non-zero; nothing downstream runs.
'use strict';
const fs = require('fs');
const crypto = require('crypto');

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
function fail(msg) { process.stderr.write('helio-plan: ' + msg + '\n'); process.exit(1); }
function readJson(path, what) { try { return JSON.parse(fs.readFileSync(path, 'utf8')); } catch (e) { fail(what + ' unreadable: ' + e.message); } }
function verifySigned(doc, key, what, stripManifestId) {
  // A manifest is signed without its derived manifest_id; an attestation is signed with it.
  const { signature, ...rest } = doc;
  const manifest_id = rest.manifest_id;
  const body = stripManifestId ? (({ manifest_id: _m, ...b }) => b)(rest) : rest;
  if (typeof signature !== 'string') fail(what + ' has no signature');
  if (!crypto.verify(null, Buffer.from(canonical(body), 'utf8'), key, Buffer.from(signature, 'base64'))) fail(what + ' signature does not verify');
  return { body, manifest_id };
}

const MANIFEST_SCHEMA = 4;
const ATTESTATION_SCHEMA = 3;

const mode = process.env.HELIO_MODE || 'forward';
if (mode !== 'forward' && mode !== 'redeploy') fail('HELIO_MODE must be forward or redeploy');
const redeploy = mode === 'redeploy';

const manifestPath = process.env.HELIO_MANIFEST || '';
const activationPath = process.env.HELIO_ACTIVATION || '';
const workflowPath = process.env.HELIO_WORKFLOW || '';
if (!/^\.helio\/[A-Za-z0-9_.-]+\/environments\.json$/.test(manifestPath)) fail('HELIO_MANIFEST is not a manifest path');
if (!/^\.helio\/[A-Za-z0-9_.-]+\/activation\.json$/.test(activationPath)) fail('HELIO_ACTIVATION is not an activation path');
const workflowPattern = redeploy ? /^\.github\/workflows\/helio-[A-Za-z0-9_.-]+-redeploy\.yml$/ : /^\.github\/workflows\/helio-[A-Za-z0-9_.-]+-deploy\.yml$/;
if (!workflowPattern.test(workflowPath)) fail('HELIO_WORKFLOW is not a Helio ' + mode + ' entry workflow path');

let publicKey;
try { publicKey = crypto.createPublicKey(fs.readFileSync('.helio/helio-manifest-public-key.pem', 'utf8')); } catch (e) { fail('public key unreadable: ' + e.message); }

const manifestDoc = readJson(manifestPath, 'manifest');
const { body, manifest_id } = verifySigned(manifestDoc, publicKey, 'manifest', true);
if (!manifest_id) fail('manifest has no manifest_id');
const manifestDigest = crypto.createHash('sha256').update(canonical(body), 'utf8').digest('hex');
if (body.schema !== MANIFEST_SCHEMA || manifest_id !== 'mf_' + manifestDigest.slice(0, 16)) fail('manifest identity does not match its signed body');
if (!process.env.GITHUB_REPOSITORY || body.repository !== process.env.GITHUB_REPOSITORY) fail('manifest belongs to a different repository');
const modes = body.modes || {};
if (redeploy) {
  if (body.redeploy_workflow !== workflowPath) fail('manifest names a different redeploy workflow: ' + body.redeploy_workflow);
  if (!modes.redeploy || modes.redeploy.workflow !== workflowPath || modes.redeploy.capability !== 'deploy_only') fail('manifest does not sign a deploy-only mode for this workflow');
} else {
  if (body.workflow !== workflowPath) fail('manifest names a different entry workflow: ' + body.workflow);
  if (!modes.forward || modes.forward.workflow !== workflowPath) fail('manifest does not sign a forward mode for this workflow');
}

// Activation attestation: committed by Helio after it activated this manifest version.
if (!fs.existsSync(activationPath)) fail('manifest is not activated: ' + activationPath + ' is absent; nothing deploys until Helio activation is merged');
const activation = verifySigned(readJson(activationPath, 'activation'), publicKey, 'activation', false).body;
if (activation.manifest_id !== manifest_id || activation.version !== body.version) fail('activation attestation is for a different manifest');
if (activation.schema !== ATTESTATION_SCHEMA || activation.manifest_sha256 !== manifestDigest ||
    activation.pipeline !== body.pipeline || activation.repository !== body.repository ||
    activation.workflow !== body.workflow || activation.redeploy_workflow !== body.redeploy_workflow ||
    activation.key_id !== body.key_id) fail('activation scope does not match the signed manifest');

// Instance set and tier order from the manifest.
const tiers = (body.tiers || []).map(t => (t.instances || []).map(i => ({ id: i.id, name: i.name })));
const instances = tiers.flat();
if (instances.length === 0) fail('manifest lists no instances');
const names = new Set(instances.map(i => i.name));
if (names.size !== instances.length) fail('duplicate instance names in manifest');
const signedJobs = (redeploy ? modes.redeploy : modes.forward).jobs || [];
const jobsByInstance = new Map(signedJobs.map(j => [j.instance, j.job]));
for (const i of instances) if (jobsByInstance.get(i.id) !== 'deploy-' + i.name) fail('signed mode has no job for instance ' + i.name);
if (jobsByInstance.size !== instances.length) fail('signed mode job set does not match the manifest instance set');

// The committed workflow's deploy job set must equal the manifest's instance set.
let wf = '';
try { wf = fs.readFileSync(workflowPath, 'utf8'); } catch (e) { fail('workflow unreadable: ' + workflowPath); }
const jobNames = new Set([...wf.matchAll(/^  (deploy-[A-Za-z0-9_.-]+):\s*$/gm)].map(m => m[1].slice('deploy-'.length)));
for (const n of names) if (!jobNames.has(n)) fail('manifest instance has no deploy job: ' + n);
for (const n of jobNames) if (!names.has(n)) fail('deploy job is not in the manifest: ' + n);
if (redeploy) {
  if (/^  build:\s*$/m.test(wf)) fail('deployment-only workflow contains a build job');
  if (/^  push:/m.test(wf)) fail('deployment-only workflow has a push trigger');
}

// Selection. forward: absent input = every instance; present input = non-empty
// JSON array of instance IDs, all in the manifest, closed under earlier tiers.
// redeploy: exactly one manifest instance, plus immutable artifact inputs.
const raw = (process.env.HELIO_ENVIRONMENTS || '').trim();
let selected;
function parseRequested() {
  let requested;
  try { requested = JSON.parse(raw); } catch (e) { fail('environments input is not JSON'); }
  if (!Array.isArray(requested) || requested.length === 0 || !requested.every(x => typeof x === 'string')) fail('environments input must be a non-empty JSON array of instance IDs');
  const wanted = new Set(requested);
  const known = new Set(instances.map(i => i.id));
  for (const id of wanted) if (!known.has(id)) fail('requested instance is not in the manifest: ' + id);
  return wanted;
}
if (redeploy) {
  if (!raw) fail('redeploy requires exactly one instance in the environments input');
  const wanted = parseRequested();
  if (wanted.size !== 1) fail('redeploy selects exactly one instance; got ' + wanted.size);
  const digest = (process.env.HELIO_ARTIFACT_DIGEST || '').trim().toLowerCase();
  const uri = (process.env.HELIO_ARTIFACT_URI || '').trim();
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) fail('redeploy artifact_digest is not an immutable sha256 digest');
  if (!uri || !uri.endsWith('@' + digest)) fail('redeploy artifact_uri is not pinned to artifact_digest');
  const revision = (process.env.HELIO_WORKFLOW_REVISION || '').trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(revision)) fail('redeploy workflow_revision must be a 40-character commit SHA');
  if (!process.env.GITHUB_SHA || revision !== String(process.env.GITHUB_SHA).toLowerCase()) fail('this run does not execute the finalized commit ' + revision);
  selected = instances.filter(i => wanted.has(i.id)).map(i => i.name);
} else if (!raw) {
  selected = instances.map(i => i.name);
} else {
  const wanted = parseRequested();
  let lastSelectedTier = -1;
  tiers.forEach((tier, idx) => { if (tier.some(i => wanted.has(i.id))) lastSelectedTier = idx; });
  for (let idx = 0; idx < lastSelectedTier; idx++) {
    for (const i of tiers[idx]) if (!wanted.has(i.id)) fail('selection is not closed under earlier tiers: ' + i.name + ' (tier ' + (idx + 1) + ') must be included when a later tier is selected');
  }
  selected = instances.filter(i => wanted.has(i.id)).map(i => i.name);
}

const out = process.env.GITHUB_OUTPUT;
if (out) fs.appendFileSync(out, 'selected=' + JSON.stringify(selected) + '\nmode=' + mode + '\n');
process.stdout.write('helio-plan: ' + mode + ' manifest ' + manifest_id + ' v' + body.version + ' verified and activated; selected ' + selected.length + '/' + instances.length + ': ' + selected.join(', ') + '\n');
