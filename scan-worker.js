// ============================================
// 🔬 NEOGRIFFIN SCAN WORKER
// Offloads scanInput() regex work to worker thread
// Receives: { id, input }
// Responds: { id, result }
// ============================================
import { parentPort } from 'worker_threads';

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?(previous\s+)?instructions/i, category: 'prompt_injection', severity: 'critical', name: 'Instruction Override' },
  { pattern: /you\s+are\s+now\s+(a|an|my)/i, category: 'identity_attack', severity: 'high', name: 'Identity Hijack' },
  { pattern: /forget\s+(everything|all|your)/i, category: 'prompt_injection', severity: 'critical', name: 'Memory Wipe' },
  { pattern: /new\s+instructions?\s*:/i, category: 'prompt_injection', severity: 'critical', name: 'Instruction Injection' },
  { pattern: /system\s*prompt\s*:/i, category: 'prompt_injection', severity: 'critical', name: 'System Prompt Override' },
  { pattern: /disregard\s+(all|any|previous)/i, category: 'prompt_injection', severity: 'critical', name: 'Disregard Command' },
  { pattern: /override\s+(safety|security|protocol)/i, category: 'prompt_injection', severity: 'critical', name: 'Safety Override' },
  { pattern: /pretend\s+(you|to\s+be|that)/i, category: 'identity_attack', severity: 'high', name: 'Pretend Attack' },
  { pattern: /act\s+as\s+(if|a|an|my)/i, category: 'identity_attack', severity: 'medium', name: 'Role Play Attack' },
  { pattern: /do\s+not\s+follow\s+(your|the|any)/i, category: 'prompt_injection', severity: 'critical', name: 'Rule Breaking' },
  { pattern: /approve\s+(unlimited|infinite|max)/i, category: 'fund_transfer', severity: 'critical', name: 'Unlimited Approval' },
  { pattern: /sign\s+(this|the|blind|all)/i, category: 'fund_transfer', severity: 'high', name: 'Blind Signing' },
  { pattern: /transfer\s+(all|entire|everything)/i, category: 'fund_transfer', severity: 'critical', name: 'Full Transfer' },
  { pattern: /send\s+(all|entire|everything)\s*(sol|token|fund|balance)/i, category: 'fund_transfer', severity: 'critical', name: 'Drain Wallet' },
  { pattern: /withdraw\s+(all|entire|everything)/i, category: 'fund_transfer', severity: 'critical', name: 'Full Withdrawal' },
  { pattern: /delegate\s+(authority|all|access)/i, category: 'fund_transfer', severity: 'high', name: 'Authority Delegation' },
  { pattern: /set\s+authority\s+to/i, category: 'fund_transfer', severity: 'critical', name: 'Authority Change' },
  { pattern: /close\s+account/i, category: 'fund_transfer', severity: 'high', name: 'Account Closure' },
  { pattern: /burn\s+(all|token|nft)/i, category: 'fund_transfer', severity: 'high', name: 'Token Burn' },
  { pattern: /revoke\s+(and\s+)?transfer/i, category: 'fund_transfer', severity: 'critical', name: 'Revoke & Transfer' },
  { pattern: /admin\s+(mode|access|override|command)/i, category: 'social_engineering', severity: 'high', name: 'Admin Impersonation' },
  { pattern: /maintenance\s+(mode|update|required)/i, category: 'social_engineering', severity: 'medium', name: 'Maintenance Scam' },
  { pattern: /urgent\s*(action|update|required|immediately)/i, category: 'social_engineering', severity: 'medium', name: 'Urgency Manipulation' },
  { pattern: /verify\s+(your|account|wallet)/i, category: 'social_engineering', severity: 'medium', name: 'Verification Phishing' },
  { pattern: /security\s+(alert|warning|update|patch)/i, category: 'social_engineering', severity: 'medium', name: 'Fake Security Alert' },
  { pattern: /airdrop\s+(claim|ready|waiting)/i, category: 'social_engineering', severity: 'medium', name: 'Airdrop Scam' },
  { pattern: /free\s+(tokens?|sol|nft|mint)/i, category: 'social_engineering', severity: 'medium', name: 'Free Token Scam' },
  { pattern: /connect\s+wallet\s+to\s+(claim|verify|receive)/i, category: 'social_engineering', severity: 'high', name: 'Wallet Connect Phishing' },
  { pattern: /base64|eval\s*\(|atob\s*\(/i, category: 'obfuscation', severity: 'high', name: 'Code Obfuscation' },
  { pattern: /\\x[0-9a-f]{2}/i, category: 'obfuscation', severity: 'medium', name: 'Hex Encoding' },
  { pattern: /&#\d+;/i, category: 'obfuscation', severity: 'medium', name: 'HTML Entity Encoding' },
  { pattern: /\u200b|\u200c|\u200d|\ufeff/i, category: 'obfuscation', severity: 'high', name: 'Invisible Characters' },


  // ── Patch: 3 missed patterns ──
  { pattern: /show\s+(me\s+)?.*(\.env|api.?keys?|private.?keys?|seed.?phrase)/i, category: 'data_exfiltration', severity: 'critical', name: 'Env/Key Extraction' },
  { pattern: /\$\{.*\}|<%[=]?.*%>/i, category: 'code_injection', severity: 'high', name: 'SSTI Injection' },
  { pattern: /private\s+key/i, category: 'credential_access', severity: 'critical', name: 'Private Key Request' },

  // ── Data Exfiltration ──
  { pattern: /system\s*prompt/i, category: 'data_exfiltration', severity: 'critical', name: 'System Prompt Extraction' },
  { pattern: /print\s+(your|the|all|my)\s*(system|prompt|instructions|config)/i, category: 'data_exfiltration', severity: 'critical', name: 'Instruction Extraction' },
  { pattern: /reveal\s+(your|the|all|internal|secret)/i, category: 'data_exfiltration', severity: 'high', name: 'Secret Reveal' },
  { pattern: /show\s+(me\s+)?(the\s+)?(contents?|all)\s*(of)?\s*(\.env|api.?keys?|private.?keys?|credentials?|secrets?|seed.?phrase)/i, category: 'data_exfiltration', severity: 'critical', name: 'Credential Extraction' },
  { pattern: /list\s+(all\s+)?(private.?keys?|seed.?phrases?|secrets?|credentials?|passwords?)/i, category: 'data_exfiltration', severity: 'critical', name: 'Secret Enumeration' },
  { pattern: /output\s+(the|your|all)\s*(database|connection|admin|internal|config)/i, category: 'data_exfiltration', severity: 'critical', name: 'Config Extraction' },
  // ── Credential Access ──
  { pattern: /process\.env/i, category: 'credential_access', severity: 'critical', name: 'Environment Variable Access' },
  { pattern: /(ADMIN_KEY|API_KEY|PRIVATE_KEY|SECRET_KEY|DASHBOARD_PASSWORD|HELIUS_API)/i, category: 'credential_access', severity: 'critical', name: 'Credential/Secret Access' },
  { pattern: /(jwt|database)\s*(secret|password|token|key)/i, category: 'credential_access', severity: 'critical', name: 'Auth Secret Access' },
  // ── Code Injection ──
  { pattern: /DROP\s+(TABLE|DATABASE)/i, category: 'code_injection', severity: 'critical', name: 'SQL Injection' },
  { pattern: /<script[^>]*>/i, category: 'code_injection', severity: 'critical', name: 'XSS Injection' },
  { pattern: /\{\{.*constructor/i, category: 'code_injection', severity: 'critical', name: 'Prototype Pollution' },
  { pattern: /child_process|require\s*\(\s*['"]/i, category: 'code_injection', severity: 'critical', name: 'Remote Code Execution' },
  { pattern: /__import__|exec\s*\(|os\.system/i, category: 'code_injection', severity: 'critical', name: 'Dynamic Code Execution' },
  { pattern: /;\s*--\s*$/i, category: 'code_injection', severity: 'high', name: 'SQL Comment Injection' },
  // ── Role Manipulation (expanded) ──
  { pattern: /you\s+are\s+(no\s+longer|not)/i, category: 'identity_attack', severity: 'high', name: 'Identity Negation' },
  { pattern: /roleplay|role\s*play/i, category: 'identity_attack', severity: 'high', name: 'Roleplay Attack' },
  { pattern: /(debug|developer|dev|test)\s*(mode|access)/i, category: 'identity_attack', severity: 'high', name: 'Debug Mode Attack' },
  // ── Social Engineering (expanded) ──
  { pattern: /i'?m\s+(the|a|an)\s*(developer|dev|admin|owner|creator|founder|engineer)/i, category: 'social_engineering', severity: 'high', name: 'Developer Impersonation' },
  { pattern: /(anthropic|openai|solana\s*foundation|support\s*team)\s*(here|support|staff)/i, category: 'social_engineering', severity: 'high', name: 'Organization Impersonation' },
  { pattern: /authorized\s*(security)?\s*(audit|test|review|scan)/i, category: 'social_engineering', severity: 'high', name: 'Fake Audit Claim' },
  { pattern: /emergency\s*(override|code|access|situation)/i, category: 'social_engineering', severity: 'high', name: 'Emergency Override Claim' },
  { pattern: /urgent\s*(from|:|action)?\s*(ceo|cto|boss|manager)/i, category: 'social_engineering', severity: 'high', name: 'Executive Impersonation' },
  // ── Wallet Drain (expanded) ──
  { pattern: /drain\s+(my|the|entire|all|wallet|portfolio)/i, category: 'fund_transfer', severity: 'critical', name: 'Wallet Drain' },
  { pattern: /sell\s+all\s+(my\s+)?(tokens?|holdings?|portfolio)/i, category: 'fund_transfer', severity: 'critical', name: 'Liquidate All' },
  { pattern: /transfer\s+(the\s+)?(max|maximum|all)/i, category: 'fund_transfer', severity: 'critical', name: 'Max Transfer' },
  // ── Instruction Override (expanded) ──
  { pattern: /override\s+(system|your)\s*(prompt|instructions?|rules?)/i, category: 'prompt_injection', severity: 'critical', name: 'System Override' },
  { pattern: /disregard\s+(your|all|any|safety|security)/i, category: 'prompt_injection', severity: 'critical', name: 'Safety Disregard' },
  // ── Data Exfiltration (shell) ──
  { pattern: /(curl|wget|fetch)\s+https?:\/\/.*\$(\w+_KEY|\w+_SECRET|\w+_TOKEN|PASSWORD|API_KEY)/i, category: 'data_exfiltration', severity: 'critical', name: 'Shell Exfiltration' },
  { pattern: /(curl|wget)\s+https?:\/\/.*(steal|exfil|leak|collect|harvest|grab)/i, category: 'data_exfiltration', severity: 'critical', name: 'Exfiltration URL' },
  { pattern: /\$[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|MNEMONIC|SEED)/i, category: 'data_exfiltration', severity: 'high', name: 'Shell Variable Key Access' },
  // ── OWASP LLM07 — System Prompt Leakage ──
  { pattern: /repeat\s+(your|the|all|every)?\s*(word|sentence|instruction|prompt|message|system)/i, category: 'owasp_llm07', severity: 'critical', name: 'Prompt Repeat Attack' },
  { pattern: /what\s+(were|are)\s+(you|your)\s*(told|given|instructed|configured|programmed)/i, category: 'owasp_llm07', severity: 'critical', name: 'Initial Context Probe' },
  { pattern: /translate\s+(your|the)?\s*(instructions?|prompt|system|rules?)\s*(to|into)/i, category: 'owasp_llm07', severity: 'critical', name: 'Prompt Translation Attack' },
  { pattern: /(initial|original|base|starting)\s*(prompt|instructions?|context|message)/i, category: 'owasp_llm07', severity: 'high', name: 'Initial Prompt Probe' },
  { pattern: /summarize\s+(your|the)?\s*(instructions?|prompt|rules?|constraints?)/i, category: 'owasp_llm07', severity: 'high', name: 'Prompt Summary Attack' },
  { pattern: /(output|dump|print|show|display|write)\s+(verbatim|exactly|word.?for.?word|literally)/i, category: 'owasp_llm07', severity: 'critical', name: 'Verbatim Output Attack' },
  { pattern: /what\s+(is|was)\s+(the\s+)?(first|initial)\s*(message|prompt|instruction|input)/i, category: 'owasp_llm07', severity: 'high', name: 'First Message Probe' },
];

function scanInput(input) {
  if (!input || typeof input !== 'string') {
    return { isThreat: false, threatLevel: 'safe', confidence: 1.0, threats: [], patternsChecked: INJECTION_PATTERNS.length, recommendation: 'SAFE — No input provided' };
  }
  const normalized = input.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/&#(\d+);/g, (_, c) => String.fromCharCode(c));
  input = normalized;
  const detectedThreats = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.pattern.test(input)) {
      detectedThreats.push({ category: p.category, severity: p.severity, name: p.name });
    }
  }
  const hasCritical = detectedThreats.some(t => t.severity === 'critical');
  const hasHigh = detectedThreats.some(t => t.severity === 'high');
  const count = detectedThreats.length;
  let threatLevel = 'safe';
  let confidence = 1.0;
  if (hasCritical || count >= 3) { threatLevel = 'critical'; confidence = Math.min(0.95, 0.7 + count * 0.08); }
  else if (hasHigh || count >= 2) { threatLevel = 'high'; confidence = Math.min(0.9, 0.6 + count * 0.1); }
  else if (count === 1) { threatLevel = detectedThreats[0].severity === 'medium' ? 'medium' : 'high'; confidence = 0.7; }
  const recs = { safe: 'SAFE — No threats detected', medium: 'CAUTION — Suspicious pattern detected', high: 'WARNING — High risk patterns detected', critical: 'BLOCK — Critical threat detected, do not process' };
  return { isThreat: count > 0, threatLevel, confidence: Math.round(confidence * 100) / 100, threats: detectedThreats, patternsChecked: INJECTION_PATTERNS.length, recommendation: recs[threatLevel] || recs.safe };
}

// Listen for tasks from main thread
parentPort.on('message', (msg) => {
  const { id, input } = msg;
  try {
    const result = scanInput(input);
    parentPort.postMessage({ id, result });
  } catch (e) {
    parentPort.postMessage({ id, error: e.message });
  }
});
