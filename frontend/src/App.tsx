import { useEffect, useMemo, useState } from "react";
import {
  API_BASE_URL,
  ApiError,
  clearStoredAccessToken,
  createAcvpSession,
  downloadAcvpSessionReportPdf,
  getAcvpServerVersion,
  getAcvpSession,
  getAcvpSessionResults,
  getAcvpSessionVectorSets,
  getAcvpVectorSetPrompt,
  getAcvpVectorSetResults,
  getStoredAccessToken,
  listAcvpSessions,
  requestNewAccessToken,
  storeAccessToken,
  submitAcvpVectorSetResults
} from "./api";
import type { AccessToken } from "./api";
import { downloadBlob, downloadJson } from "./acvp";
import JsonViewer from "./components/JsonViewer";
import DiagnosticReport from "./components/DiagnosticReport";
import ValidationReport from "./components/ValidationReport";
import { buildRegistrationAlgorithms } from "./registration";
import { FIPS_REGISTRY, getFipsConfig } from "./registry";
import type {
  AcvpParameterSet,
  AcvpRevision,
  AcvpServerVersion,
  AcvpSessionDetail,
  AcvpSessionRegistration,
  AcvpSessionSummary,
  AcvpVectorSetId,
  AcvpVectorSetSummary,
  CapabilityMode,
  FipsVersionConfig,
  FipsVersionId,
  JsonValue,
  MlKemFunction,
  NormalizedSessionResultsView,
  NormalizedVectorSetResultView,
  NormalizedVectorSetView
} from "./types";

const DEFAULT_CAMPAIGN_SEED = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
const ACCESS_TOKEN_REQUIRED_MESSAGE =
  "Access token required. Click Get New Access Token to continue.";
const ACCESS_TOKEN_EXPIRED_MESSAGE =
  "Your access token has expired or is invalid. Click Get New Access Token to continue.";

interface Notice {
  text: string;
  tone: "error" | "success" | "info";
}

export default function App() {
  const [activeFipsId, setActiveFipsId] = useState<FipsVersionId>("FIPS204");
  const config = useMemo(() => getFipsConfig(activeFipsId), [activeFipsId]);
  const [selectedModes, setSelectedModes] = useState<CapabilityMode[]>(["keyGen"]);
  const [selectedRevisions, setSelectedRevisions] = useState<
    Partial<Record<CapabilityMode, AcvpRevision>>
  >({ keyGen: "FIPS204" });
  const [selectedParameterSets, setSelectedParameterSets] = useState<AcvpParameterSet[]>([
    "ML-DSA-44"
  ]);
  const [selectedFunctions, setSelectedFunctions] = useState<MlKemFunction[]>([]);
  const [campaignSeed, setCampaignSeed] = useState(DEFAULT_CAMPAIGN_SEED);
  const [label, setLabel] = useState("ML-DSA registration");
  const [sessions, setSessions] = useState<AcvpSessionSummary[]>([]);
  const [activeSession, setActiveSession] = useState<AcvpSessionDetail | null>(null);
  const [vectorSets, setVectorSets] = useState<AcvpVectorSetSummary[]>([]);
  const [activeVectorSetId, setActiveVectorSetId] = useState<AcvpVectorSetId | null>(null);
  const [activeVectorSet, setActiveVectorSet] = useState<NormalizedVectorSetView | null>(null);
  const [uploadedResponse, setUploadedResponse] = useState<JsonValue | null>(null);
  const [uploadedResponseName, setUploadedResponseName] = useState("");
  const [uploadedResponseSha256, setUploadedResponseSha256] = useState("");
  const [vectorResult, setVectorResult] = useState<NormalizedVectorSetResultView | null>(null);
  const [sessionResults, setSessionResults] = useState<NormalizedSessionResultsView | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [reportGeneratedAt, setReportGeneratedAt] = useState<string | null>(null);
  const [printReportKind, setPrintReportKind] =
    useState<"summary" | "diagnostic">("summary");
  const [serverVersion, setServerVersion] = useState<AcvpServerVersion | null>(null);
  const [accessToken, setAccessToken] = useState<AccessToken | null>(() => getStoredAccessToken());

  const activeVectorSummary =
    vectorSets.find((vector) => vector.vsId === activeVectorSetId) ?? null;
  const seedError = validateCampaignSeed(campaignSeed);
  const registrationError = validateRegistration(
    selectedModes,
    selectedParameterSets,
    selectedFunctions,
    config,
    seedError
  );
  const sessionReportAvailable = isSessionReportAvailable(activeSession, sessionResults);
  const diagnosticReportAvailable = Boolean(vectorResult);

  function printReport(kind: "summary" | "diagnostic") {
    setPrintReportKind(kind);

    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => window.print());
    });
  }

  useEffect(() => {
    getAcvpServerVersion()
      .then(setServerVersion)
      .catch(() => setServerVersion(null));
  }, []);

  useEffect(() => {
    if (!accessToken) {
      setNotice((current) =>
        current?.text === ACCESS_TOKEN_EXPIRED_MESSAGE
          ? current
          : { text: ACCESS_TOKEN_REQUIRED_MESSAGE, tone: "info" }
      );
      return;
    }
    const expiresAt = Date.parse(accessToken.expiresAt);
    const remaining = expiresAt - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      expireAccessToken();
      return;
    }
    refreshSessions().catch(showError);
    const expiryTimer = window.setTimeout(expireAccessToken, remaining);
    return () => window.clearTimeout(expiryTimer);
  }, [accessToken?.accessToken]);

  function expireAccessToken() {
    clearStoredAccessToken();
    setAccessToken(null);
    setNotice({ text: ACCESS_TOKEN_EXPIRED_MESSAGE, tone: "error" });
  }

  async function getNewAccessToken() {
    await runBusy(async () => {
      const issued = await requestNewAccessToken();
      storeAccessToken(issued);
      setAccessToken(issued);
      const minutes = Math.ceil(issued.expiresIn / 60);
      setNotice({ text: `A new access token is active for ${minutes} minutes.`, tone: "success" });
    });
  }

  async function refreshSessions() {
    const summaries = await listAcvpSessions();
    const detailed = await Promise.all(
      summaries.map(async (summary) => {
        try {
          return { ...summary, ...(await getAcvpSession(summary.testSessionId)) };
        } catch {
          return summary;
        }
      })
    );
    setSessions(detailed);
  }

  function selectAlgorithm(id: FipsVersionId) {
    const nextConfig = getFipsConfig(id);
    setActiveFipsId(id);
    setSelectedModes([...nextConfig.defaultModes]);
    setSelectedRevisions(defaultRevisions(nextConfig));
    setSelectedParameterSets([...nextConfig.defaultParameterSets]);
    setSelectedFunctions([...(nextConfig.defaultFunctions ?? [])]);
    setLabel(`${nextConfig.algorithm} registration`);
    setNotice(null);
  }

  async function createSession() {
    if (registrationError) {
      setNotice({ text: registrationError, tone: "error" });
      return;
    }
    await runBusy(async () => {
      const payload: AcvpSessionRegistration = {
        algorithms: buildRegistrationAlgorithms({
          config,
          modes: selectedModes,
          parameterSets: selectedParameterSets,
          functions: selectedFunctions,
          revisions: selectedRevisions
        }),
        label,
        autoGenerateVectorSets: true,
        testsPerGroup: 1
      };
      if (campaignSeed.trim()) {
        payload.campaignSeed = campaignSeed.trim();
      }
      const created = await createAcvpSession(payload);
      await refreshSessions();
      await activateSession(created.testSessionId);
      setNotice({ text: "ACVP test session created.", tone: "success" });
    });
  }

  async function activateSession(sessionId: string) {
    setNotice(null);
    await runBusy(async () => {
      const [session, vectors] = await Promise.all([
        getAcvpSession(sessionId),
        getAcvpSessionVectorSets(sessionId)
      ]);
      setActiveSession(session);
      setVectorSets(vectors);
      clearVectorWorkspace();
      const vsId = vectors[0]?.vsId ?? null;
      if (vsId !== null) {
        await openVectorSet(session.testSessionId, vsId);
      }
    });
  }

  async function openVectorSet(
    sessionId: string,
    vsId: AcvpVectorSetId
  ) {
    setNotice(null);
    const vector = await getAcvpVectorSetPrompt(sessionId, vsId);
    setActiveVectorSetId(vsId);
    setActiveVectorSet(vector);
    setUploadedResponse(null);
    setUploadedResponseName("");
    setUploadedResponseSha256("");
    setReportGeneratedAt(null);
    setVectorResult(null);
    setSessionResults(null);
    setVectorSets(await getAcvpSessionVectorSets(sessionId));
  }

  async function loadResponse(file: File | null) {
    if (!file) {
      return;
    }

    setNotice(null);

    try {
      const fileBytes = await file.arrayBuffer();
      const text = new TextDecoder().decode(fileBytes);
      const parsedResponse = JSON.parse(text) as JsonValue;
      const digest = await crypto.subtle.digest("SHA-256", fileBytes);
      const sha256 = Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");

      setUploadedResponse(parsedResponse);
      setUploadedResponseName(file.name);
      setUploadedResponseSha256(sha256);
      setVectorResult(null);
      setSessionResults(null);
      setReportGeneratedAt(null);
    } catch {
      setUploadedResponseSha256("");
      setNotice({ text: "The selected response file is not valid JSON.", tone: "error" });
    }
  }

  async function submitResponse() {
    if (!activeSession || activeVectorSetId === null || uploadedResponse === null) {
      setNotice({ text: "Select a vector set and response file first.", tone: "error" });
      return;
    }
    await runBusy(async () => {
      await submitAcvpVectorSetResults(
        activeSession.testSessionId,
        activeVectorSetId,
        uploadedResponse
      );
      await refreshResults(activeSession.testSessionId, activeVectorSetId);
      await refreshSessions();
      setNotice({
        text: "Response accepted. NIST GenVal disposition has been refreshed.",
        tone: "success"
      });
    });
  }

  async function refreshResults(
    sessionId = activeSession?.testSessionId,
    vsId = activeVectorSetId
  ) {
    if (!sessionId || vsId === null) {
      return;
    }
    const [result, results, session, vectors] = await Promise.all([
      getAcvpVectorSetResults(sessionId, vsId),
      getAcvpSessionResults(sessionId),
      getAcvpSession(sessionId),
      getAcvpSessionVectorSets(sessionId)
    ]);
    setVectorResult(result);
    setSessionResults(results);
    setActiveSession(session);
    setVectorSets(vectors);
    setReportGeneratedAt(new Date().toISOString());
  }

  function clearVectorWorkspace() {
    setActiveVectorSetId(null);
    setActiveVectorSet(null);
    setUploadedResponse(null);
    setUploadedResponseName("");
    setUploadedResponseSha256("");
    setReportGeneratedAt(null);
    setVectorResult(null);
    setSessionResults(null);
  }

  function resetWorkspace() {
    setNotice(null);
    setActiveSession(null);
    setVectorSets([]);
    clearVectorWorkspace();
  }

  function downloadArtifact(kind: "prompt" | "results" | "session-results") {
    if (activeVectorSetId === null) {
      return;
    }
    const value =
      kind === "prompt"
        ? activeVectorSet?.raw
        : kind === "results"
          ? vectorResult?.raw
          : sessionResults?.raw;
    if (value === undefined || value === null) {
      return;
    }
    downloadJson(value, `${artifactStem(activeVectorSet, activeVectorSummary, activeVectorSetId)}-${kind}.json`);
  }

  async function downloadPdfReport() {
    if (!activeSession || !sessionReportAvailable) {
      return;
    }
    await runBusy(async () => {
      const file = await downloadAcvpSessionReportPdf(activeSession.testSessionId);
      downloadBlob(file.blob, file.filename);
      setNotice({ text: "PDF validation report downloaded.", tone: "success" });
    });
  }

  async function runBusy(work: () => Promise<void>) {
    setIsBusy(true);
    try {
      await work();
    } catch (error) {
      showError(error);
    } finally {
      setIsBusy(false);
    }
  }

  function showError(error: unknown) {
    if (error instanceof ApiError && error.status === 401) {
      expireAccessToken();
      return;
    }
    setNotice({ text: formatError(error), tone: "error" });
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">NCCU ACVP Server</p>
          <h1>ACVP Test Sessions</h1>
          <p className="topbar-detail">{API_BASE_URL}</p>
        </div>
        <div className="status-cluster">
          <StatusChip label="Workflow: Strict" tone="strict" />
          <StatusChip label="Execution: NIST GenVal" tone="ready" />
          <StatusChip label={`Token: ${accessToken ? "active" : "required"}`} tone={accessToken ? "ready" : "warning"} />
          <button type="button" onClick={getNewAccessToken} disabled={isBusy}>
            Get New Access Token
          </button>
          <button type="button" onClick={() => refreshSessions().catch(showError)} disabled={isBusy || !accessToken}>
            Refresh
          </button>
          <button type="button" className="secondary" onClick={resetWorkspace} disabled={isBusy}>
            Clear
          </button>
        </div>
      </header>

      {notice ? (
        <div className={`notice ${notice.tone}`} role={notice.tone === "error" ? "alert" : "status"}>
          {notice.text}
        </div>
      ) : null}

      <section className="workflow-grid">
        <section className="panel stack registration-panel">
          <div className="panel-header">
            <h2>{config.label} Registration</h2>
            <StatusChip
              label={`${config.algorithm} / ${selectedRevisionLabel(
                config,
                selectedModes,
                selectedRevisions
              )}`}
              tone="info"
            />
          </div>
          <div className="control-group">
            <span>Algorithm</span>
            <div className="segmented algorithm-selector" aria-label="Algorithm">
              {FIPS_REGISTRY.filter((item) => item.enabled).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={item.id === activeFipsId ? "active" : "secondary"}
                  aria-pressed={item.id === activeFipsId}
                  onClick={() => selectAlgorithm(item.id)}
                  disabled={isBusy}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
          <CapabilityControls
            config={config}
            selectedModes={selectedModes}
            selectedRevisions={selectedRevisions}
            selectedParameterSets={selectedParameterSets}
            selectedFunctions={selectedFunctions}
            disabled={isBusy}
            onToggleMode={(mode) => setSelectedModes(toggleValue(selectedModes, mode))}
            onSelectRevision={(mode, revision) =>
              setSelectedRevisions({ ...selectedRevisions, [mode]: revision })
            }
            onToggleParameterSet={(value) =>
              setSelectedParameterSets(toggleValue(selectedParameterSets, value))
            }
            onToggleFunction={(value) =>
              setSelectedFunctions(toggleValue(selectedFunctions, value))
            }
          />
          <label className="field">
            <span>Label</span>
            <input value={label} onChange={(event) => setLabel(event.target.value)} disabled={isBusy} />
          </label>
          <label className={`field ${seedError ? "invalid" : ""}`}>
            <span>Campaign seed</span>
            <input
              value={campaignSeed}
              onChange={(event) => setCampaignSeed(event.target.value)}
              disabled={isBusy}
              aria-invalid={Boolean(seedError)}
            />
            {seedError ? <small className="field-error">{seedError}</small> : null}
          </label>
          {registrationError && registrationError !== seedError ? (
            <p className="field-error">{registrationError}</p>
          ) : null}
          <button type="button" onClick={createSession} disabled={isBusy || !accessToken || Boolean(registrationError)}>
            Create test session
          </button>
        </section>

        <section className="panel stack sessions-panel">
          <div className="panel-header">
            <h2>Test Sessions</h2>
            <StatusChip label={String(sessions.length)} tone="info" />
          </div>
          <div className="session-list">
            {sessions.map((session) => (
              <button
                key={session.testSessionId}
                type="button"
                className={`session-row ${activeSession?.testSessionId === session.testSessionId ? "active-row" : ""}`}
                onClick={() => activateSession(session.testSessionId)}
                disabled={isBusy}
              >
                <span>{session.label || session.testSessionId}</span>
                <strong>{session.status}</strong>
                <small>
                  {session.algorithm ?? "Unknown algorithm"} · {session.vectorSetCount ?? session.vectorSetIds.length} vector(s)
                </small>
              </button>
            ))}
            {sessions.length === 0 ? <p className="empty-state">No test sessions.</p> : null}
          </div>
        </section>

        <section className="panel stack wide-panel vector-panel">
          <div className="panel-header">
            <h2>Vector Sets</h2>
            <StatusChip label={activeSession?.status ?? "none"} tone="info" />
          </div>
          <div className="vector-toolbar">
            {vectorSets.map((vector) => (
              <button
                key={vector.vsId}
                type="button"
                className={activeVectorSetId === vector.vsId ? "active" : "secondary"}
                onClick={() => activeSession && openVectorSet(activeSession.testSessionId, vector.vsId)}
                disabled={isBusy}
              >
                {vector.mode || "vector"} / vsId {vector.vsId} / {vector.status}
              </button>
            ))}
          </div>
          <MetadataGrid
            items={[
              ["Algorithm", activeVectorSet?.prompt.algorithm ?? activeVectorSummary?.algorithm ?? "-"],
              ["Revision", activeVectorSet?.prompt.revision ?? activeVectorSummary?.revision ?? "-"],
              ["Mode", activeVectorSet?.prompt.mode ?? activeVectorSummary?.mode ?? "-"],
              ["vsId", activeVectorSetId === null ? "-" : String(activeVectorSetId)],
              ["Provider", activeVectorSummary?.provider ?? activeVectorSummary?.providerName ?? "nist-genval"],
              ["Status", activeVectorSummary?.status ?? activeVectorSet?.status ?? "-"]
            ]}
          />
          <div className="actions">
            <button
              type="button"
              className="secondary"
              onClick={() => downloadArtifact("prompt")}
              disabled={!activeVectorSet?.raw}
            >
              Download prompt JSON
            </button>
          </div>
          <JsonPane title="Prompt" value={activeVectorSet?.prompt ?? null} />
        </section>

        <section className="panel stack response-panel">
          <div className="panel-header">
            <h2>IUT Response</h2>
            <StatusChip label={uploadedResponseName || "not loaded"} tone="info" />
          </div>
          <label className={`file-button ${!activeVectorSet || isBusy ? "disabled" : ""}`}>
            <span>Upload response JSON</span>
            <input
              type="file"
              accept="application/json,.json"
              disabled={!activeVectorSet || isBusy}
              onChange={(event) => {
                void loadResponse(event.currentTarget.files?.[0] ?? null);
                event.currentTarget.value = "";
              }}
            />
          </label>
          <button
            type="button"
            onClick={submitResponse}
            disabled={uploadedResponse === null || !activeVectorSet || isBusy}
          >
            Submit response
          </button>
          <JsonPane title="Uploaded response" value={uploadedResponse} />
        </section>

        <section className="panel stack wide-panel results-panel">
          <div className="panel-header">
            <h2>Validation Results</h2>
            <StatusChip label={vectorResult?.disposition ?? "unreceived"} tone="info" />
          </div>
          <div className="actions">
            <button
              type="button"
              onClick={() =>
                activeSession &&
                activeVectorSetId !== null &&
                runBusy(() => refreshResults(activeSession.testSessionId, activeVectorSetId))
              }
              disabled={!activeSession || activeVectorSetId === null || isBusy}
            >
              Refresh results
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => downloadArtifact("results")}
              disabled={!vectorResult?.raw}
            >
              Download vector results JSON
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => downloadArtifact("session-results")}
              disabled={!sessionResults?.raw}
            >
              Download session results JSON
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => printReport("summary")}
              disabled={(!vectorResult && !sessionResults) || isBusy}
            >
              Print Summary Report
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => printReport("diagnostic")}
              disabled={!diagnosticReportAvailable || isBusy}
              title={
                diagnosticReportAvailable
                  ? "Print detailed validation report"
                  : "Diagnostic Report is available after validation results are loaded."
              }
            >
              Print Diagnostic Report
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => void downloadPdfReport()}
              disabled={!sessionReportAvailable || isBusy}
              title={
                sessionReportAvailable
                  ? "Download the complete test-session validation report"
                  : "The PDF report is available after every vector set validation completes."
              }
            >
              Download PDF report
            </button>
          </div>
          <ResultList result={vectorResult} sessionResults={sessionResults} />
          <JsonPane title="Vector set results" value={vectorResult?.raw ?? null} />
          <JsonPane title="Test session results" value={sessionResults?.raw ?? null} />
        </section>

      </section>
      <div className="print-report-container" aria-hidden="true">
        {printReportKind === "diagnostic" ? (
          <DiagnosticReport
            session={activeSession}
            vectorSet={activeVectorSummary}
            vectorSetView={activeVectorSet}
            responseFileName={uploadedResponseName}
            responseSha256={uploadedResponseSha256}
            reportGeneratedAt={reportGeneratedAt}
            serverVersion={serverVersion}
            vectorResult={vectorResult}
            sessionResults={sessionResults}
          />
        ) : (
          <ValidationReport
            session={activeSession}
            vectorSet={activeVectorSummary}
            vectorSetView={activeVectorSet}
            responseFileName={uploadedResponseName}
            responseSha256={uploadedResponseSha256}
            reportGeneratedAt={reportGeneratedAt}
            serverVersion={serverVersion}
            vectorResult={vectorResult}
            sessionResults={sessionResults}
          />
        )}
      </div>
    </main>
  );
}

interface CapabilityControlsProps {
  config: FipsVersionConfig;
  selectedModes: CapabilityMode[];
  selectedRevisions: Partial<Record<CapabilityMode, AcvpRevision>>;
  selectedParameterSets: AcvpParameterSet[];
  selectedFunctions: MlKemFunction[];
  disabled: boolean;
  onToggleMode: (mode: CapabilityMode) => void;
  onSelectRevision: (mode: CapabilityMode, revision: AcvpRevision) => void;
  onToggleParameterSet: (value: AcvpParameterSet) => void;
  onToggleFunction: (value: MlKemFunction) => void;
}

function CapabilityControls({
  config,
  selectedModes,
  selectedRevisions,
  selectedParameterSets,
  selectedFunctions,
  disabled,
  onToggleMode,
  onSelectRevision,
  onToggleParameterSet,
  onToggleFunction
}: CapabilityControlsProps) {
  const showFunctions = config.id === "FIPS203" && selectedModes.includes("encapDecap");
  return (
    <>
      <div className="control-group">
        <span>Modes</span>
        <div className="segmented">
          {config.modes.filter((mode) => mode.enabled).map((mode) => (
            <button
              key={mode.id}
              type="button"
              className={selectedModes.includes(mode.id) ? "active" : "secondary"}
              aria-pressed={selectedModes.includes(mode.id)}
              onClick={() => onToggleMode(mode.id)}
              disabled={disabled}
            >
              {mode.label}
            </button>
          ))}
        </div>
      </div>
      {selectedModes.map((mode) => {
        const modeConfig = config.modes.find((item) => item.id === mode);
        if (!modeConfig) return null;
        return (
          <label className="field" key={`${mode}-revision`}>
            <span>{mode} revision</span>
            <select
              value={selectedRevisions[mode] ?? modeConfig.defaultRevision}
              onChange={(event) =>
                onSelectRevision(mode, event.target.value as AcvpRevision)
              }
              disabled={disabled || modeConfig.revisions.length === 1}
            >
              {modeConfig.revisions.map((revision) => (
                <option key={revision} value={revision}>{revision}</option>
              ))}
            </select>
          </label>
        );
      })}
      <div className="control-group">
        <span>Parameter sets</span>
        <div className="segmented">
          {config.parameterSets.map((value) => (
            <button
              key={value}
              type="button"
              className={selectedParameterSets.includes(value) ? "active" : "secondary"}
              aria-pressed={selectedParameterSets.includes(value)}
              onClick={() => onToggleParameterSet(value)}
              disabled={disabled}
            >
              {value}
            </button>
          ))}
        </div>
      </div>
      {showFunctions ? (
        <div className="control-group">
          <span>ML-KEM functions</span>
          <div className="function-grid">
            {config.functions?.map((value) => (
              <label className="checkbox-field function-option" key={value}>
                <input
                  type="checkbox"
                  checked={selectedFunctions.includes(value)}
                  onChange={() => onToggleFunction(value)}
                  disabled={disabled}
                />
                <span>{value}</span>
              </label>
            ))}
          </div>
        </div>
      ) : null}
    </>
  );
}

function defaultRevisions(
  config: FipsVersionConfig
): Partial<Record<CapabilityMode, AcvpRevision>> {
  return Object.fromEntries(
    config.modes.map((mode) => [mode.id, mode.defaultRevision])
  ) as Partial<Record<CapabilityMode, AcvpRevision>>;
}

function selectedRevisionLabel(
  config: FipsVersionConfig,
  modes: CapabilityMode[],
  revisions: Partial<Record<CapabilityMode, AcvpRevision>>
): string {
  const values = modes.map((mode) => {
    const modeConfig = config.modes.find((item) => item.id === mode);
    return revisions[mode] ?? modeConfig?.defaultRevision ?? config.revision;
  });
  return [...new Set(values)].join(", ") || config.revision;
}

function MetadataGrid({ items }: { items: [string, string][] }) {
  return (
    <dl className="metadata-grid">
      {items.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function StatusChip({ label, tone }: { label: string; tone: string }) {
  return <span className={`state-chip ${tone}`}>{label}</span>;
}

function JsonPane({ title, value }: { title: string; value: unknown }) {
  return (
    <div className="json-pane">
      <h3>{title}</h3>
      {value === null || value === undefined ? (
        <p className="empty-state">No JSON.</p>
      ) : (
        <JsonViewer value={value} />
      )}
    </div>
  );
}

function ResultList({
  result,
  sessionResults
}: {
  result: NormalizedVectorSetResultView | null;
  sessionResults: NormalizedSessionResultsView | null;
}) {
  if (!result && !sessionResults) {
    return <p className="empty-state">No results loaded.</p>;
  }
  return (
    <div className="session-results-list">
      <strong>Vector disposition: {result?.disposition ?? "unreceived"}</strong>
      {sessionResults?.results.map((item, index) => (
        <div className="session-result-item" key={`${item.vectorSetUrl}-${index}`}>
          <span>{item.vectorSetUrl}</span>
          <strong>{item.disposition ?? item.status}</strong>
        </div>
      ))}
    </div>
  );
}

function isSessionReportAvailable(
  session: AcvpSessionDetail | null,
  results: NormalizedSessionResultsView | null
): boolean {
  if (!session || session.vectorSetCount < 1) {
    return false;
  }
  if (session.pendingVectorSetCount === 0) {
    return true;
  }
  if (!results || results.results.length !== session.vectorSetCount) {
    return false;
  }
  const pendingDispositions = new Set(["unreceived", "received", "incomplete", "pending"]);
  return results.results.every((item) => {
    const disposition = (item.disposition ?? item.status).trim().toLowerCase();
    return disposition.length > 0 && !pendingDispositions.has(disposition);
  });
}

function validateRegistration(
  modes: CapabilityMode[],
  parameterSets: AcvpParameterSet[],
  functions: MlKemFunction[],
  config: FipsVersionConfig,
  seedError: string | null
): string | null {
  if (modes.length === 0 || parameterSets.length === 0) {
    return "Select at least one mode and parameter set.";
  }
  if (config.id === "FIPS203" && modes.includes("encapDecap") && functions.length === 0) {
    return "Select at least one ML-KEM function for encapDecap.";
  }
  return seedError;
}

function validateCampaignSeed(value: string): string | null {
  if (!value) {
    return null;
  }
  if (
    !/^[0-9a-fA-F]+$/.test(value) ||
    value.length % 2 !== 0 ||
    value.length < 32 ||
    value.length > 128
  ) {
    return "Campaign seed must be 32-128 hexadecimal characters.";
  }
  return null;
}

function artifactStem(
  vector: NormalizedVectorSetView | null,
  summary: AcvpVectorSetSummary | null,
  vsId: AcvpVectorSetId
): string {
  const algorithm = vector?.prompt.algorithm ?? summary?.algorithm ?? "ACVP";
  const mode = vector?.prompt.mode ?? summary?.mode ?? "vector";
  return `${algorithm}-${mode}-vs${vsId}`;
}

function formatError(error: unknown): string {
  if (error instanceof ApiError) {
    const code = error.code ?? "ACVP_ERROR";
    const path = error.path ? `; path: ${error.path}` : "";
    return `${code} — ${error.message} (HTTP ${error.status}${path})`;
  }
  return error instanceof Error ? error.message : "Operation failed.";
}

function toggleValue<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}
