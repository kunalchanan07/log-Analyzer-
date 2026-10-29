import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Search, 
  Plus, 
  Check, 
  X, 
  FileCode, 
  Zap,
  SlidersHorizontal,
  AlertCircle
} from 'lucide-react';
import { DetectionRule, Severity, ThreatCategory } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface RulesManagerProps {
  rules: DetectionRule[];
  lang: Language;
  onToggleRule: (ruleId: string) => void;
  onAddRule: (newRule: DetectionRule) => void;
}

export const RulesManager: React.FC<RulesManagerProps> = ({
  rules,
  lang,
  onToggleRule,
  onAddRule
}) => {
  const t = TRANSLATIONS[lang];
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'all'>('all');
  const [isModalOpen, setIsModalOpen] = useState(false);

  // New Rule Form State
  const [name, setName] = useState('');
  const [category, setCategory] = useState<ThreatCategory>('unauthorized_access');
  const [severity, setSeverity] = useState<Severity>('high');
  const [mitreId, setMitreId] = useState('T1078');
  const [mitreTactic, setMitreTactic] = useState('Defense Evasion');
  const [pattern, setPattern] = useState('');
  const [regexString, setRegexString] = useState('');
  const [description, setDescription] = useState('');
  const [remediation, setRemediation] = useState('');

  const filteredRules = rules.filter(r => {
    if (selectedSeverity !== 'all' && r.severity !== selectedSeverity) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        r.name.toLowerCase().includes(q) ||
        r.mitreId.toLowerCase().includes(q) ||
        r.pattern.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !pattern.trim()) return;

    const newRule: DetectionRule = {
      id: `RULE-CUSTOM-${Date.now().toString().slice(-4)}`,
      name,
      severity,
      category,
      mitreId: mitreId.trim() || 'T1000',
      mitreTactic: mitreTactic.trim() || 'Execution',
      pattern,
      regexString: regexString.trim() || pattern,
      enabled: true,
      hits: 0,
      description: description.trim() || 'Custom SOC detection signature rule.',
      remediation: remediation.trim() || 'Scrutinize affected host and enforce zero-trust boundary.'
    };

    onAddRule(newRule);
    setIsModalOpen(false);
    // Reset form
    setName('');
    setPattern('');
    setRegexString('');
    setDescription('');
    setRemediation('');
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 border border-rose-500/30 bg-rose-500/10';
      case 'high':
        return 'text-amber-400 border border-amber-500/30 bg-amber-500/10';
      case 'medium':
        return 'text-sky-400 border border-sky-500/30 bg-sky-500/10';
      default:
        return 'text-slate-400 border border-slate-700 bg-slate-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
            <span>{t.rulesTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {lang === 'pa'
              ? 'SIEM ਸਿਗਮਾ ਤੇ ਯਾਰਾ ਨਿਯਮ, ਪੈਟਰਨ ਮੈਚਿੰਗ ਅਤੇ MITRE ATT&CK ਤਕਨੀਕਾਂ'
              : 'Sigma & heuristic detection rules actively inspecting all ingested log payloads.'}
          </p>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow-sm shadow-cyan-900/30 transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>{t.addCustomRule}</span>
        </button>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative w-full sm:flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={lang === 'pa' ? 'ਨਿਯਮ, MITRE ID ਜਾਂ ਪੈਟਰਨ ਨਾਲ ਖੋਜੋ...' : 'Search rules by name, MITRE ID, or pattern...'}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value as any)}
          className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="all">{t.allSeverities}</option>
          <option value="critical">{t.critical}</option>
          <option value="high">{t.high}</option>
          <option value="medium">{t.medium}</option>
          <option value="low">{t.low}</option>
        </select>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            className={`p-5 rounded-xl border transition-all ${
              rule.enabled 
                ? 'bg-slate-900/80 border-slate-800 hover:border-slate-700' 
                : 'bg-slate-950/40 border-slate-900 opacity-60'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(rule.severity)}`}>
                    {rule.severity}
                  </span>
                  <span className="text-xs font-mono text-cyan-400 font-semibold">
                    {rule.id}
                  </span>
                  <span className="text-xs font-mono text-indigo-400">
                    MITRE {rule.mitreId}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white mt-2">
                  {rule.name}
                </h3>
              </div>

              {/* Toggle switch */}
              <button
                onClick={() => onToggleRule(rule.id)}
                className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors cursor-pointer shrink-0 ${
                  rule.enabled ? 'bg-cyan-600' : 'bg-slate-800'
                }`}
                aria-label={`Toggle rule ${rule.name}`}
              >
                <div
                  className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                    rule.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              {rule.description}
            </p>

            {/* Pattern inspect box */}
            <div className="mt-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-300 break-all">
              <span className="text-slate-500 font-sans mr-1">{lang === 'pa' ? 'ਸਿਗਨੇਚਰ ਪੈਟਰਨ:' : 'Signature Pattern:'}</span>
              <code>{rule.regexString || rule.pattern}</code>
            </div>

            <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500 font-mono">
              <span className="text-cyan-400/90 font-semibold tabular-nums">
                {rule.hits} {t.hits}
              </span>
              <span className="text-slate-400">
                {rule.mitreTactic}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Add Custom Rule Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                <span>{t.addCustomRule}</span>
              </h2>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  {lang === 'pa' ? 'ਨਿਯਮ ਦਾ ਨਾਮ' : 'Rule Name'}
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Unusual Outbound SSH Tunnel"
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    {lang === 'pa' ? 'ਗੰਭੀਰਤਾ' : 'Severity'}
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as Severity)}
                    className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="critical">{t.critical}</option>
                    <option value="high">{t.high}</option>
                    <option value="medium">{t.medium}</option>
                    <option value="low">{t.low}</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    MITRE Technique ID
                  </label>
                  <input
                    type="text"
                    value={mitreId}
                    onChange={(e) => setMitreId(e.target.value)}
                    placeholder="T1078"
                    className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  {lang === 'pa' ? 'ਖੋਜ ਪੈਟਰਨ ਜਾਂ Regex' : 'Detection Regex or Keywords'}
                </label>
                <input
                  type="text"
                  required
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="e.g. (tunnel\\.sh|nc\\s+-e|/bin/sh\\s+-i)"
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  {lang === 'pa' ? 'ਵੇਰਵਾ' : 'Rule Description'}
                </label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Explain the security risk and attacker intent..."
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  {lang === 'pa' ? 'ਸਿਫਾਰਸ਼ ਕੀਤੀ ਕਾਰਵਾਈ (Remediation)' : 'Remediation Steps'}
                </label>
                <input
                  type="text"
                  value={remediation}
                  onChange={(e) => setRemediation(e.target.value)}
                  placeholder="e.g. Block outbound port 4444 and quarantine host"
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:text-white bg-slate-800 transition-colors"
                >
                  {t.close}
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-colors"
                >
                  {lang === 'pa' ? 'ਨਿਯਮ ਸੁਰੱਖਿਅਤ ਕਰੋ' : 'Save Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
