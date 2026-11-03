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
        return 'text-rose-400 border border-rose-500/30 bg-rose-500/10 font-bold';
      case 'high':
        return 'text-yellow-400 border border-yellow-400/30 bg-yellow-400/10 font-bold';
      case 'medium':
        return 'text-amber-300 border border-amber-400/30 bg-amber-400/10';
      default:
        return 'text-neutral-400 border border-neutral-700 bg-neutral-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2.5 uppercase">
            <ShieldCheck className="w-6 h-6 text-yellow-400 stroke-[2.5]" />
            <span>{t.rulesTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-neutral-300 font-medium mt-1">
            {lang === 'pa'
              ? 'SIEM ਸਿਗਮਾ ਤੇ ਯਾਰਾ ਨਿਯਮ, ਪੈਟਰਨ ਮੈਚਿੰਗ ਅਤੇ MITRE ATT&CK ਤਕਨੀਕਾਂ'
              : 'Sigma & heuristic detection rules actively inspecting all ingested log payloads.'}
          </p>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-yellow-400 hover:bg-yellow-300 text-neutral-950 text-xs font-bold rounded-xl shadow-md shadow-yellow-500/20 transition-all cursor-pointer active:scale-95"
        >
          <Plus className="w-4 h-4 text-neutral-950 stroke-[2.5]" />
          <span>{t.addCustomRule}</span>
        </button>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative w-full sm:flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={lang === 'pa' ? 'ਨਿਯਮ, MITRE ID ਜਾਂ ਪੈਟਰਨ ਨਾਲ ਖੋਜੋ...' : 'Search rules by name, MITRE ID, or pattern...'}
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-white placeholder:text-neutral-500 focus:outline-none focus:border-yellow-400 focus:ring-1 focus:ring-yellow-400/50 transition-colors"
          />
        </div>

        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value as any)}
          className="px-3.5 py-2.5 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-white font-medium focus:outline-none focus:border-yellow-400 cursor-pointer"
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
            className={`p-5 rounded-2xl border transition-all ${
              rule.enabled 
                ? 'bg-neutral-900/90 border-neutral-800 hover:border-yellow-400/40 shadow-xl' 
                : 'bg-neutral-950/40 border-neutral-900 opacity-60'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(rule.severity)}`}>
                    {rule.severity}
                  </span>
                  <span className="text-xs font-mono text-yellow-400 font-bold">
                    {rule.id}
                  </span>
                  <span className="text-xs font-mono text-neutral-300 font-semibold bg-neutral-800 px-1.5 py-0.2 rounded border border-neutral-700">
                    MITRE {rule.mitreId}
                  </span>
                </div>
                <h3 className="text-sm font-extrabold text-white mt-2">
                  {rule.name}
                </h3>
              </div>

              {/* Toggle switch */}
              <button
                onClick={() => onToggleRule(rule.id)}
                className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors cursor-pointer shrink-0 ${
                  rule.enabled ? 'bg-yellow-400 shadow-sm shadow-yellow-500/30' : 'bg-neutral-800'
                }`}
                aria-label={`Toggle rule ${rule.name}`}
              >
                <div
                  className={`bg-neutral-950 w-4 h-4 rounded-full shadow-md transform transition-transform ${
                    rule.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            <p className="text-xs text-neutral-300 mt-2 leading-relaxed">
              {rule.description}
            </p>

            {/* Pattern inspect box */}
            <div className="mt-3 p-3 rounded-xl bg-neutral-950 border border-neutral-800/80 font-mono text-[11px] text-white break-all">
              <span className="text-neutral-500 font-sans mr-1">{lang === 'pa' ? 'ਸਿਗਨੇਚਰ ਪੈਟਰਨ:' : 'Signature Pattern:'}</span>
              <code className="text-yellow-300 font-bold">{rule.regexString || rule.pattern}</code>
            </div>

            <div className="mt-3 pt-3 border-t border-neutral-800 flex items-center justify-between text-xs font-mono">
              <span className="text-yellow-400 font-bold tabular-nums">
                {rule.hits} {t.hits}
              </span>
              <span className="text-neutral-400">
                {rule.mitreTactic}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Add Custom Rule Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in">
          <div className="w-full max-w-lg rounded-2xl bg-neutral-900 border border-neutral-700 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <h2 className="text-base font-black text-white flex items-center gap-2 uppercase tracking-wide">
                <FileCode className="w-5 h-5 text-yellow-400" />
                <span>{t.addCustomRule}</span>
              </h2>
              <button
                onClick={() => setIsModalOpen(false)}
                className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-white font-bold mb-1">
                  {lang === 'pa' ? 'ਨਿਯਮ ਦਾ ਨਾਮ' : 'Rule Name'}
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Unusual Outbound SSH Tunnel"
                  className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-white font-bold mb-1">
                    {lang === 'pa' ? 'ਗੰਭੀਰਤਾ' : 'Severity'}
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as Severity)}
                    className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400"
                  >
                    <option value="critical">{t.critical}</option>
                    <option value="high">{t.high}</option>
                    <option value="medium">{t.medium}</option>
                    <option value="low">{t.low}</option>
                  </select>
                </div>

                <div>
                  <label className="block text-white font-bold mb-1">
                    MITRE Technique ID
                  </label>
                  <input
                    type="text"
                    value={mitreId}
                    onChange={(e) => setMitreId(e.target.value)}
                    placeholder="T1078"
                    className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-white font-bold mb-1">
                  {lang === 'pa' ? 'ਖੋਜ ਪੈਟਰਨ ਜਾਂ Regex' : 'Detection Regex or Keywords'}
                </label>
                <input
                  type="text"
                  required
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="e.g. (tunnel\\.sh|nc\\s+-e|/bin/sh\\s+-i)"
                  className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400 font-mono"
                />
              </div>

              <div>
                <label className="block text-white font-bold mb-1">
                  {lang === 'pa' ? 'ਵੇਰਵਾ' : 'Rule Description'}
                </label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Explain the security risk and attacker intent..."
                  className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400"
                />
              </div>

              <div>
                <label className="block text-white font-bold mb-1">
                  {lang === 'pa' ? 'ਸਿਫਾਰਸ਼ ਕੀਤੀ ਕਾਰਵਾਈ (Remediation)' : 'Remediation Steps'}
                </label>
                <input
                  type="text"
                  value={remediation}
                  onChange={(e) => setRemediation(e.target.value)}
                  placeholder="e.g. Block outbound port 4444 and quarantine host"
                  className="w-full p-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-white focus:outline-none focus:border-yellow-400"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-neutral-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-neutral-300 hover:text-white bg-neutral-800 transition-colors cursor-pointer"
                >
                  {t.close}
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-yellow-400 hover:bg-yellow-300 text-neutral-950 font-bold transition-all shadow-md shadow-yellow-500/20 cursor-pointer"
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
