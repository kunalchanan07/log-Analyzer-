import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Helper for local SOC AI fallback if key is not configured or fails
function generateLocalSocAnalysis(payload: {
  incidentTitle?: string;
  category?: string;
  attackerIp?: string;
  targetHost?: string;
  mitreTechnique?: string;
  logs?: string[];
}) {
  const { incidentTitle, category, attackerIp, targetHost, mitreTechnique, logs } = payload;
  return `### SOC Incident Briefing: ${incidentTitle || 'Suspicious Threat Activity'}

**Severity**: High / Critical
**Target Vector**: ${category || 'Unknown'} (MITRE ATT&CK: ${mitreTechnique || 'T1190'})
**Adversary IP**: \`${attackerIp || '185.220.101.5'}\`
**Compromised / Targeted Asset**: \`${targetHost || 'gateway-edge-01'}\`

#### 1. Threat Actor Hypothesis & Technical Breakdown
The observed telemetry depicts a coordinated offensive operation. Indicators demonstrate signature patterns matching known automated scanners and weaponized exploitation frameworks targeting exposed application and operating system primitives. The payload indicates intent to bypass authentication controls and establish persistent foothold.

#### 2. Correlated Indicators of Compromise (IOCs)
- **Host**: \`${targetHost || 'internal-core'}\`
- **Network Source**: \`${attackerIp || 'External IP'}\`
- **Evidence Snippets**:
${logs?.slice(0, 3).map(l => `  > \`${l.substring(0, 120)}...\``).join('\n') || '  > Telemetry captured in SIEM pipeline'}

#### 3. Immediate Containment Playbook (Tier 2/3 SOC)
1. **Network Boundary**: Immediately execute IP block at edge firewall (Null-route or border ACL drop for \`${attackerIp || 'attacker'}\`).
2. **Host Quarantine**: Isolate \`${targetHost || 'host'}\` via EDR client agent to prevent lateral movement.
3. **Session Revocation**: Invalidate all active JWT tokens, SSH keys, or Kerberos tickets tied to affected accounts.
4. **Credential Rotation**: Force password and multi-factor authentication (MFA) reset.

#### 4. Post-Incident Hardening & Detection Tuning
- Deploy WAF inspection rules specifically blocking parameterized SQLi and path traversal sequences.
- Restrict SSH/RDP ingress strictly behind Zero Trust VPN gateways.
- Review Volume Shadow Copy and process creation auditing (Sysmon Event ID 1).`;
}

// AI Forensic Analysis endpoint
app.post('/api/analyze-threat', async (req: Request, res: Response) => {
  try {
    const { incidentTitle, category, attackerIp, targetHost, mitreTechnique, logs } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
      // Return high-quality heuristic cybersecurity analyst output
      const localReport = generateLocalSocAnalysis({
        incidentTitle,
        category,
        attackerIp,
        targetHost,
        mitreTechnique,
        logs
      });
      return res.json({ analysis: localReport, source: 'heuristic-engine' });
    }

    const ai = new GoogleGenAI({ apiKey });
    const prompt = `You are a Senior Principal SOC Security Analyst and Threat Hunter investigating an active security incident.
Provide an incident triage report in markdown format.

Details:
Incident Title: ${incidentTitle || 'Unknown'}
Attack Category: ${category || 'Unknown'}
Attacker IP: ${attackerIp || 'Unknown'}
Target Host / Asset: ${targetHost || 'Unknown'}
MITRE ATT&CK Technique: ${mitreTechnique || 'Unknown'}
Raw Telemetry Logs:
${JSON.stringify(logs?.slice(0, 5) || [], null, 2)}

Structure your report with:
1. Executive Summary & Threat Actor Intent
2. Forensic Telemetry Analysis (Explaining what the attacker attempted)
3. Indicators of Compromise (IOCs)
4. Concrete Step-by-Step Containment & Remediation Playbook (Firewall, EDR, Identity)
5. Detection Rule / Sigma Tuning Recommendation
Keep it concise, realistic, and directly actionable for SOC L2/L3 engineers.`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
    });

    return res.json({
      analysis: response.text || generateLocalSocAnalysis({ incidentTitle, category, attackerIp, targetHost, mitreTechnique, logs }),
      source: 'gemini-ai'
    });
  } catch (err: any) {
    console.error('Gemini API Error, falling back to heuristic analyst:', err?.message);
    const fallback = generateLocalSocAnalysis(req.body);
    return res.json({ analysis: fallback, source: 'fallback-engine' });
  }
});

// Mount Vite middleware in development mode
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (_req, res) => {
      res.sendFile('dist/index.html', { root: '.' });
    });
  }

  app.listen(PORT, () => {
    console.log(`AegisSOC server running on http://localhost:${PORT}`);
  });
}

startServer();
