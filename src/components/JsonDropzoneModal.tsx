import React, { useState, useRef, useEffect } from 'react';
import {
  X,
  UploadCloud,
  FileCode,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Shield,
  Layers
} from 'lucide-react';
import { detectProviderSchema, parseAndScoreIngestedJson, SAMPLE_PAYLOADS } from '../utils/riskEngine';
import { CloudIdentity } from '../types';

interface JsonDropzoneModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIngestSuccess: (newIdentities: CloudIdentity[]) => void;
}

export const JsonDropzoneModal: React.FC<JsonDropzoneModalProps> = ({
  isOpen,
  onClose,
  onIngestSuccess
}) => {
  const [jsonText, setJsonText] = useState<string>('');
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [detectedInfo, setDetectedInfo] = useState<{ provider: string; confidence: string } | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Update schema detection as text changes
  useEffect(() => {
    if (!jsonText.trim()) {
      setDetectedInfo(null);
      setParseError(null);
      return;
    }

    try {
      const parsed = JSON.parse(jsonText);
      const detection = detectProviderSchema(parsed);
      setDetectedInfo(detection);
      setParseError(null);
    } catch {
      setDetectedInfo(null);
      setParseError('Invalid JSON format');
    }
  }, [jsonText]);

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const processFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setJsonText(content);
    };
    reader.readAsText(file);
  };

  const loadPreset = (key: 'awsWildcard' | 'azureOwner' | 'gcpProjectOwner') => {
    const payload = SAMPLE_PAYLOADS[key];
    setJsonText(JSON.stringify(payload, null, 2));
  };

  const handleIngest = () => {
    try {
      const parsed = JSON.parse(jsonText);
      const result = parseAndScoreIngestedJson(parsed);

      if (result.success && result.identities.length > 0) {
        onIngestSuccess(result.identities);
        onClose();
      } else {
        setParseError(result.message || 'Failed to ingest policy schema');
      }
    } catch (err: any) {
      setParseError(`JSON Syntax Error: ${err?.message || 'Invalid JSON'}`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center">
              <UploadCloud className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Ingest Cloud Access Configuration</h3>
              <p className="text-xs text-slate-400">
                Drop or paste raw JSON policies (AWS IAM, Azure RBAC, or GCP Cloud IAM)
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4 overflow-y-auto">
          {/* Preset Sample Buttons */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-semibold uppercase tracking-wider text-[11px]">
                Quick Test with Sample Cloud Policies:
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => loadPreset('awsWildcard')}
                className="px-3 py-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all text-left"
              >
                <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                <span>AWS Wildcard Admin</span>
              </button>

              <button
                type="button"
                onClick={() => loadPreset('azureOwner')}
                className="px-3 py-2 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-300 border border-blue-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all text-left"
              >
                <span className="h-2 w-2 rounded-full bg-blue-400"></span>
                <span>Azure Sub Owner</span>
              </button>

              <button
                type="button"
                onClick={() => loadPreset('gcpProjectOwner')}
                className="px-3 py-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all text-left"
              >
                <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                <span>GCP Project Owner SA</span>
              </button>
            </div>
          </div>

          {/* Drag & Drop Zone */}
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-all ${
              dragActive
                ? 'border-cyan-500 bg-cyan-950/20'
                : 'border-slate-800 hover:border-slate-700 bg-slate-950/50'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              onChange={handleFileChange}
              className="hidden"
            />
            <div className="flex flex-col items-center justify-center gap-1.5">
              <FileCode className="h-6 w-6 text-slate-500" />
              <p className="text-xs text-slate-300 font-medium">
                <span className="text-cyan-400 font-semibold">Click to upload JSON file</span> or drag and drop
              </p>
              <p className="text-[10px] text-slate-500">Supports AWS IAM Policies, Azure RBAC exports, GCP bindings</p>
            </div>
          </div>

          {/* Live JSON Textarea */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <label className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">
                Or Paste JSON Document:
              </label>
              {jsonText && (
                <button
                  type="button"
                  onClick={() => setJsonText('')}
                  className="text-slate-500 hover:text-slate-300 text-[11px]"
                >
                  Clear
                </button>
              )}
            </div>

            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              placeholder='Paste policy JSON here (e.g. { "Statement": [ { "Action": "*", "Resource": "*" } ] })'
              className="w-full h-44 bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none leading-relaxed"
            />
          </div>

          {/* Real-time Schema Detection Banner */}
          {detectedInfo && (
            <div
              className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
                detectedInfo.provider === 'AWS'
                  ? 'bg-amber-950/20 border-amber-500/30 text-amber-300'
                  : detectedInfo.provider === 'Azure'
                  ? 'bg-blue-950/20 border-blue-500/30 text-blue-300'
                  : detectedInfo.provider === 'GCP'
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : detectedInfo.provider === 'Unified'
                  ? 'bg-purple-950/20 border-purple-500/30 text-purple-300'
                  : 'bg-slate-800/40 border-slate-700 text-slate-400'
              }`}
            >
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
                <div>
                  <span className="font-bold">Detected Schema: {detectedInfo.provider}</span>
                  <p className="text-[11px] opacity-80">{detectedInfo.confidence}</p>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded bg-slate-900 text-[10px] font-mono border border-slate-700">
                Ready for CIEM Ingest
              </span>
            </div>
          )}

          {parseError && (
            <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-900/40 text-xs text-rose-300 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-rose-400 flex-shrink-0" />
              <span>{parseError}</span>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/90 flex items-center justify-between">
          <span className="text-xs text-slate-400">
            Engine automatically maps to unified CIEM data model and computes risk.
          </span>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
            >
              Cancel
            </button>

            <button
              type="button"
              onClick={handleIngest}
              disabled={!jsonText.trim() || Boolean(parseError)}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-cyan-600/20 transition-all"
            >
              <Sparkles className="h-4 w-4" />
              <span>Ingest & Score Identity</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
