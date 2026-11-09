import React, { useState } from "react";
import {
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Search,
  Calendar,
  CheckCircle2,
  XCircle,
  FileKey,
  Globe,
  Layers,
  Fingerprint,
  Link2,
  Clock,
  ExternalLink,
  ShieldX,
  Info,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient } from "../../services/apiClient";
import { TlsInspectResponse } from "../../services/types";

export const TlsView: React.FC = () => {
  const [hostname, setHostname] = useState<string>("github.com");
  const [port, setPort] = useState<number>(443);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TlsInspectResponse | null>(null);

  const handleInspect = async (e?: React.FormEvent, overrideHost?: string) => {
    if (e) e.preventDefault();
    const targetHost = (overrideHost !== undefined ? overrideHost : hostname).trim();
    if (!targetHost) {
      setError("Please specify a target hostname to inspect.");
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const data = await apiClient.inspectTls(targetHost, port);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to complete TLS handshake probe.");
    } finally {
      setIsLoading(false);
    }
  };

  const runQuickTest = (host: string) => {
    setHostname(host);
    handleInspect(undefined, host);
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A+":
      case "A":
        return "text-emerald-400 bg-emerald-950/40 border-emerald-500/40";
      case "B":
        return "text-cyan-400 bg-cyan-950/40 border-cyan-500/40";
      case "C":
        return "text-amber-400 bg-amber-950/40 border-amber-500/40";
      default:
        return "text-red-400 bg-red-950/40 border-red-500/40";
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header & Target Input */}
      <Card className="border-slate-800 bg-slate-900/70 shadow-xl">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-purple-400" />
              <span>TLS & Certificate Intelligence Engine</span>
            </CardTitle>
            <span className="text-xs text-slate-400 font-mono">
              OpenSSL Cryptographic Handshake & x509 Parser
            </span>
          </div>
          <CardDescription>
            Inspects certificate validity periods, Subject Alternative Names (SANs), hostname matching,
            chain trust status, Certificate Transparency (CT) evidence, public key dimensions, and cryptographic anomalies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleInspect} className="space-y-4">
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <Globe className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                <Input
                  type="text"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="e.g. github.com or wikipedia.org"
                  className="pl-10 h-11 text-sm font-mono text-white placeholder:text-slate-500 border-slate-700 bg-slate-950/90"
                  disabled={isLoading}
                />
              </div>
              <div className="w-full sm:w-28">
                <Input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value) || 443)}
                  placeholder="Port"
                  className="h-11 text-sm font-mono text-white border-slate-700 bg-slate-950/90"
                  disabled={isLoading}
                />
              </div>
              <Button
                type="submit"
                disabled={isLoading}
                className="h-11 px-6 font-semibold bg-purple-600 hover:bg-purple-700 text-white"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin text-purple-200" />
                    <span>Auditing Handshake...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4 mr-2" />
                    <span>Audit Certificate</span>
                  </>
                )}
              </Button>
            </div>
          </form>

          {/* Controlled Benchmark & Test Fixtures */}
          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-500 font-mono text-[11px]">Controlled Test Fixtures:</span>
            <button
              type="button"
              onClick={() => runQuickTest("github.com")}
              className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white font-mono text-[11px] hover:bg-slate-700 transition-colors"
            >
              github.com (Valid A+)
            </button>
            <button
              type="button"
              onClick={() => runQuickTest("wikipedia.org")}
              className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white font-mono text-[11px] hover:bg-slate-700 transition-colors"
            >
              wikipedia.org (Let's Encrypt)
            </button>
            <button
              type="button"
              onClick={() => runQuickTest("expired.badssl.com")}
              className="px-2.5 py-1 rounded bg-red-950/40 border border-red-800/50 text-red-300 hover:text-white font-mono text-[11px] hover:bg-red-900/60 transition-colors"
            >
              expired.badssl.com (Expired Anomaly)
            </button>
            <button
              type="button"
              onClick={() => runQuickTest("self-signed.badssl.com")}
              className="px-2.5 py-1 rounded bg-amber-950/40 border border-amber-800/50 text-amber-300 hover:text-white font-mono text-[11px] hover:bg-amber-900/60 transition-colors"
            >
              self-signed.badssl.com (Untrusted Anchor)
            </button>
            <button
              type="button"
              onClick={() => runQuickTest("wrong.host.badssl.com")}
              className="px-2.5 py-1 rounded bg-blue-950/40 border border-blue-800/50 text-blue-300 hover:text-white font-mono text-[11px] hover:bg-blue-900/60 transition-colors"
            >
              wrong.host.badssl.com (Hostname Mismatch)
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Critical Security Notice */}
      <Alert className="border-cyan-900/50 bg-cyan-950/20 text-cyan-200">
        <Info className="h-4 w-4 text-cyan-400" />
        <AlertTitle className="text-xs font-mono font-bold text-cyan-300">
          Core Security Principle: Transport Encryption ≠ Domain Legitimacy
        </AlertTitle>
        <AlertDescription className="text-xs text-slate-300 leading-relaxed">
          A valid TLS certificate confirms encrypted transit and domain name control, but does not prove website legitimacy or business trustworthiness. Over 80% of active credential harvesting and phishing sites operate behind valid, automated DV certificates.
        </AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>TLS Inspection Fault</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {result && (
        <div className="space-y-6">
          {/* Main Handshake Assessment Banner */}
          <Card className="border-slate-800 bg-slate-900/80 shadow-2xl">
            <CardHeader className="pb-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="text-xl font-bold font-mono text-white">
                      {result.hostname}:{result.port}
                    </h3>
                    <Badge
                      variant={result.connected ? "clean" : "destructive"}
                      className="text-xs font-mono"
                    >
                      {result.connected ? "HANDSHAKE ESTABLISHED" : "CONNECTION FAILED"}
                    </Badge>
                    {result.hostname_matches !== undefined && (
                      <Badge
                        variant={result.hostname_matches ? "clean" : "destructive"}
                        className="text-xs font-mono"
                      >
                        {result.hostname_matches ? "HOSTNAME MATCH: PASS" : "HOSTNAME MISMATCH"}
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Subject Common Name: <strong className="text-slate-200">{result.subject || result.hostname}</strong>
                  </p>
                </div>

                {/* Grade Badge */}
                <div
                  className={`rounded-xl border px-4 py-2 flex items-center gap-3 ${getGradeColor(
                    result.grade
                  )}`}
                >
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-mono tracking-wider opacity-80 block">
                      Security Posture
                    </span>
                    <span className="text-2xl font-black font-mono">
                      Grade {result.grade}
                    </span>
                  </div>
                </div>
              </div>
            </CardHeader>

            <CardContent className="space-y-6 pt-2">
              {/* Observable Anomalies Strip */}
              {result.anomalies && result.anomalies.length > 0 && (
                <div className="space-y-2 p-3.5 rounded-lg border border-red-900/50 bg-red-950/20">
                  <span className="text-xs font-mono font-bold text-red-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Cryptographic & Trust Anomalies Detected ({result.anomalies.length})</span>
                  </span>
                  <div className="space-y-2 pt-1">
                    {result.anomalies.map((a, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded border border-red-900/30 bg-slate-950/80 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                      >
                        <div>
                          <span className="font-mono font-bold text-red-300">[{a.code}] {a.title}: </span>
                          <span className="text-slate-300">{a.description}</span>
                        </div>
                        <Badge variant="destructive" className="text-[10px] uppercase shrink-0 font-mono">
                          {a.severity}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Validity Timeline & Dates */}
              <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                    <Calendar className="w-4 h-4 text-cyan-400" />
                    <span>Certificate Validity Timeline</span>
                  </span>
                  <span
                    className={`text-xs font-mono font-bold ${
                      result.is_expired
                        ? "text-red-400"
                        : (result.days_remaining ?? 0) < 15
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {result.is_expired
                      ? `EXPIRED (${Math.abs(result.days_remaining || 0)} days ago)`
                      : `${result.days_remaining ?? "N/A"} days remaining`}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono pt-1">
                  <div className="p-2.5 rounded border border-slate-800/80 bg-slate-900/70">
                    <span className="text-[10px] text-slate-500 uppercase block">Valid From</span>
                    <span className="text-slate-300 font-semibold">
                      {result.valid_from ? new Date(result.valid_from).toUTCString() : "N/A"}
                    </span>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800/80 bg-slate-900/70">
                    <span className="text-[10px] text-slate-500 uppercase block">Valid Until</span>
                    <span className="text-slate-300 font-semibold">
                      {result.valid_to ? new Date(result.valid_to).toUTCString() : "N/A"}
                    </span>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800/80 bg-slate-900/70">
                    <span className="text-[10px] text-slate-500 uppercase block">Trust Store Status</span>
                    <span className={result.is_self_signed ? "text-amber-400 font-semibold" : result.certificate_validity?.chain_trusted ? "text-emerald-400 font-semibold" : "text-red-400 font-semibold"}>
                      {result.is_self_signed ? "Self-Signed (Untrusted)" : result.certificate_validity?.chain_trusted ? "Trusted Root Anchor" : "Untrusted Chain"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Certificate Chain Visualization */}
              {result.certificate_chain && result.certificate_chain.length > 0 && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-purple-400" />
                    <span>Certificate Hierarchy & Trust Chain ({result.certificate_chain.length} Nodes)</span>
                  </h4>

                  <div className="space-y-2">
                    {result.certificate_chain.map((node, idx) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-lg border font-mono text-xs flex flex-col md:flex-row md:items-center justify-between gap-2 ${
                          node.is_leaf
                            ? "border-cyan-500/30 bg-slate-950/80"
                            : node.is_root
                            ? "border-emerald-500/30 bg-slate-950/60"
                            : "border-slate-800 bg-slate-950/50"
                        }`}
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                              {node.is_leaf ? "Leaf Certificate" : node.is_root ? "Root Anchor" : `Intermediate CA #${idx}`}
                            </span>
                            <span className="text-white font-semibold">{node.subject}</span>
                          </div>
                          <span className="text-slate-400 text-[11px] block">
                            Issued by: {node.issuer}
                          </span>
                        </div>

                        <div className="flex items-center gap-3 shrink-0">
                          {node.sha256_fingerprint && (
                            <span className="text-[10px] text-slate-500 truncate max-w-[140px]" title={node.sha256_fingerprint}>
                              FP: {node.sha256_fingerprint.slice(0, 14)}...
                            </span>
                          )}
                          <Badge
                            variant={node.trusted ? "clean" : "destructive"}
                            className="text-[10px] uppercase font-mono"
                          >
                            {node.trusted ? "Trusted Anchor" : "Untrusted"}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Cryptographic Parameters & Certificate Transparency Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Cryptographic Parameters */}
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
                  <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                    <FileKey className="w-4 h-4 text-purple-400" />
                    <span>Cryptographic Specifications</span>
                  </span>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Public Key Algorithm:</span>
                      <span className="text-slate-200">
                        {result.key_algorithm || "RSA"} ({result.key_size || 2048} bits)
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Signature Algorithm:</span>
                      <span className="text-slate-200 truncate max-w-[200px]">
                        {result.signature_algorithm || "sha256WithRSAEncryption"}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">TLS Protocol Version:</span>
                      <span className="text-cyan-300 font-bold">{result.protocol_version || "TLSv1.3"}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Cipher Suite:</span>
                      <span className="text-slate-200 truncate max-w-[200px]" title={result.cipher_suite}>
                        {result.cipher_suite || "Unknown"}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Forward Secrecy (PFS):</span>
                      <span className={result.security_posture?.has_pfs ? "text-emerald-400 font-bold" : "text-amber-400"}>
                        {result.security_posture?.has_pfs ? "Supported (ECDHE/DHE)" : "Not Detected"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Certificate Transparency (CT) Evidence */}
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
                  <span className="text-xs font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                    <Fingerprint className="w-4 h-4 text-emerald-400" />
                    <span>Certificate Transparency (CT) Evidence</span>
                  </span>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">CT Logging Status:</span>
                      <span className={result.certificate_transparency?.is_verified ? "text-emerald-400 font-bold" : "text-slate-400"}>
                        {result.certificate_transparency?.status === "verified_embedded_scts"
                          ? "VERIFIED EMBEDDED"
                          : "UNAVAILABLE IN RUNTIME"}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Embedded SCT Count:</span>
                      <span className="text-slate-200 font-bold">
                        {result.certificate_transparency?.sct_count ?? 0} SCT(s)
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Log Operators:</span>
                      <span className="text-slate-300 truncate max-w-[200px]">
                        {result.certificate_transparency?.operators?.length
                          ? result.certificate_transparency.operators.join(", ")
                          : "None"}
                      </span>
                    </div>
                    <div className="pt-1">
                      <span className="text-[10px] text-slate-400 leading-normal block">
                        {result.certificate_transparency?.details}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* SHA-256 and SHA-1 Fingerprints */}
              {result.sha256_fingerprint && (
                <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/70 font-mono text-xs space-y-1">
                  <span className="text-slate-500 uppercase text-[10px] block">SHA-256 Certificate Fingerprint:</span>
                  <span className="text-slate-200 break-all select-all">{result.sha256_fingerprint}</span>
                </div>
              )}

              {/* SANs (Subject Alternative Names) */}
              {result.subject_alt_names && result.subject_alt_names.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 uppercase font-mono tracking-wider mb-2">
                    Subject Alternative Names (SANs) ({result.subject_alt_names.length})
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {result.subject_alt_names.map((san, idx) => (
                      <Badge
                        key={idx}
                        variant="outline"
                        className="text-[11px] font-mono text-slate-300 border-slate-800 bg-slate-950/60"
                      >
                        {san}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};
