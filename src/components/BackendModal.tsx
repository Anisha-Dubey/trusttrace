import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { X, Terminal, Copy, Check, Server, Database, Shield } from 'lucide-react';
import { sound } from '../utils/audio';

interface BackendModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (msg: string) => void;
}

export default function BackendModal({ isOpen, onClose, onShowToast }: BackendModalProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!isOpen) return null;

  const copySnippet = (text: string, index: number) => {
    sound.playClick(650);
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIndex(index);
      onShowToast('Command copied to clipboard');
      setTimeout(() => setCopiedIndex(null), 2000);
    });
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-black/40 backdrop-blur-xs"
        />

        {/* Modal Window */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="relative w-full max-w-2xl handdrawn-card border border-[rgb(0_0_0/10%)] bg-[#ffffff] p-4 sm:p-8 space-y-5 sm:space-y-6 shadow-2xl z-10 max-h-[90vh] overflow-y-auto text-[#040404]"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[rgb(0_0_0/10%)] pb-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 handdrawn-box bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] text-[#040404]">
                <Terminal className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm sm:text-base font-bold text-[#040404] font-heading tracking-[-0.03em]">
                  FastAPI Server &amp; Continuous Pipeline
                </h3>
                <p className="text-[11px] sm:text-xs text-[#6b6b6b] font-body mt-0.5">
                  Autonomous client-side triage mode or pair with live Python runtime
                </p>
              </div>
            </div>

            <button
              onClick={() => {
                sound.playClick(500);
                onClose();
              }}
              className="p-1.5 handdrawn-pill text-[#6b6b6b] hover:text-[#040404] hover:bg-[#f6f6f6] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Modal Content */}
          <div className="space-y-4 text-xs font-mono text-[#040404]">
            <p className="leading-relaxed font-body text-xs text-[#6b6b6b]">
              TRUSTTRACE operates in standalone client-side triage mode with full fidelity. To attach the production Python FastAPI server with persistent SQLite telemetry and continuous collectors:
            </p>

            {/* Snippet 1 */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[#6b6b6b] text-[11px] font-mono">
                <span>Option 1: Windows One-Click Batch Script</span>
                <button
                  onClick={() => copySnippet('launch.bat', 1)}
                  className="hover:text-[#040404] flex items-center gap-1 font-semibold transition-colors"
                >
                  {copiedIndex === 1 ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy</span>
                </button>
              </div>
              <pre className="p-3 handdrawn-box bg-[#101010] border border-[rgb(0_0_0/10%)] text-white text-xs font-mono overflow-x-auto">
                launch.bat
              </pre>
            </div>

            {/* Snippet 2 */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[#6b6b6b] text-[11px] font-mono">
                <span>Option 2: Direct Python CLI Runner</span>
                <button
                  onClick={() => copySnippet('python run_app.py --port 8000', 2)}
                  className="hover:text-[#040404] flex items-center gap-1 font-semibold transition-colors"
                >
                  {copiedIndex === 2 ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy</span>
                </button>
              </div>
              <pre className="p-3 handdrawn-box bg-[#101010] border border-[rgb(0_0_0/10%)] text-white text-xs font-mono overflow-x-auto">
                python run_app.py --port 8000
              </pre>
            </div>

            {/* Architecture Pipeline Spec */}
            <div className="pt-2 border-t border-[rgb(0_0_0/10%)] space-y-2">
              <span className="text-[#6b6b6b] uppercase tracking-wider text-[11px] font-bold font-mono">
                Worker Architecture Allocation:
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div className="p-3 handdrawn-box bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] space-y-1">
                  <div className="text-[#040404] font-bold flex items-center gap-1.5 font-heading">
                    <Shield className="w-3.5 h-3.5 text-[#040404]" />
                    <span>Worker 01 Intake</span>
                  </div>
                  <div className="text-[#6b6b6b] font-body">SSRF filtering, canonical host parsing, homoglyph detection.</div>
                </div>

                <div className="p-3 handdrawn-box bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] space-y-1">
                  <div className="text-[#040404] font-bold flex items-center gap-1.5 font-heading">
                    <Database className="w-3.5 h-3.5 text-[#040404]" />
                    <span>Worker 02 Community</span>
                  </div>
                  <div className="text-[#6b6b6b] font-body">Decentralized feed, anti-Sybil deduplication, SQLite storage.</div>
                </div>

                <div className="p-3 handdrawn-box bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] space-y-1">
                  <div className="text-[#040404] font-bold flex items-center gap-1.5 font-heading">
                    <Server className="w-3.5 h-3.5 text-[#040404]" />
                    <span>Worker 03 Adjudication</span>
                  </div>
                  <div className="text-[#6b6b6b] font-body">Deterministic synthesis across 4 dimensions and invariants.</div>
                </div>

                <div className="p-3 handdrawn-box bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] space-y-1">
                  <div className="text-[#040404] font-bold flex items-center gap-1.5 font-heading">
                    <Terminal className="w-3.5 h-3.5 text-[#040404]" />
                    <span>Worker 04 Passport</span>
                  </div>
                  <div className="text-[#6b6b6b] font-body">Evidence Passport presentation, audit lineage, JSON schema.</div>
                </div>
              </div>
            </div>

            {/* Endpoints */}
            <div className="pt-2 border-t border-[rgb(0_0_0/10%)] space-y-1.5 text-[11px]">
              <span className="text-[#6b6b6b] uppercase tracking-wider font-bold font-mono">FastAPI Local Endpoints:</span>
              <ul className="list-disc list-inside space-y-1 text-[#6b6b6b] font-mono">
                <li>Interactive Dashboard: <span className="text-[#040404] font-bold">http://localhost:8000/</span></li>
                <li>Interactive Swagger Docs: <span className="text-[#040404] font-bold">http://localhost:8000/docs</span></li>
                <li>System Health Check: <span className="text-[#040404] font-bold">http://localhost:8000/health</span></li>
              </ul>
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              onClick={() => {
                sound.playClick(500);
                onClose();
              }}
              className="px-4 py-2 handdrawn-pill bg-[#101010] hover:bg-[#131313] text-white font-medium text-xs font-mono transition-colors shadow-xs"
            >
              Close Console
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
