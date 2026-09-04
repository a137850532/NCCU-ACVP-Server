import type {
  AcvpServerVersion,
  AcvpSessionDetail,
  AcvpStrictVectorSetResultTest,
  AcvpVectorSetSummary,
  NormalizedSessionResultsView,
  NormalizedVectorSetResultView,
  NormalizedVectorSetView
} from "../types";

interface DiagnosticReportProps {
  session: AcvpSessionDetail | null;
  vectorSet: AcvpVectorSetSummary | null;
  vectorSetView: NormalizedVectorSetView | null;
  responseFileName: string;
  responseSha256: string;
  reportGeneratedAt: string | null;
  serverVersion: AcvpServerVersion | null;
  vectorResult: NormalizedVectorSetResultView | null;
  sessionResults: NormalizedSessionResultsView | null;
}

export default function DiagnosticReport({
  session,
  vectorSet,
  vectorSetView,
  responseFileName,
  responseSha256,
  reportGeneratedAt,
  serverVersion,
  vectorResult,
  sessionResults
}: DiagnosticReportProps) {
  if (!session) {
    return null;
  }

  const tests = vectorResult?.tests ?? [];
  const failedTests = tests.filter((test) => isFailure(test.result));
  const testGroups = vectorSetView?.prompt.testGroups ?? [];
  const parameterSets = uniqueStrings(
    testGroups.map((group) => group.parameterSet)
  );
  const testTypes = uniqueStrings(
    testGroups.map((group) => group.testType)
  );
  const sampleVectorSet =
    typeof vectorSetView?.prompt.isSample === "boolean"
      ? vectorSetView.prompt.isSample
      : typeof session.isSample === "boolean"
        ? session.isSample
        : undefined;
  const tgIdByTcId = buildTestGroupMap(vectorSetView);
  const testGroupById = new Map(
    testGroups.map((group) => [String(group.tgId), group])
  );
  const failedTestGroups = new Map<
    string,
    {
      tgId: number | string | undefined;
      parameterSet?: string;
      testType?: string;
      tests: AcvpStrictVectorSetResultTest[];
    }
  >();

  for (const test of failedTests) {
    const tgId = resolveTgId(test, tgIdByTcId);
    const key = tgId === undefined ? "unknown" : String(tgId);
    const group = failedTestGroups.get(key);

    if (group) {
      group.tests.push(test);
    } else {
      const promptGroup = testGroupById.get(key);

      failedTestGroups.set(key, {
        tgId,
        parameterSet: promptGroup?.parameterSet,
        testType: promptGroup?.testType,
        tests: [test]
      });
    }
  }
  const vectorSetId = vectorSet?.vsId ?? vectorSet?.vectorSetId ?? "unknown";
  const reportId = `NCCU-ACVP-DIAG-${session.testSessionId}-VS${String(vectorSetId)}`;
  const disposition = vectorResult?.disposition ?? "unreceived";
  const overallFailed = failedTests.length > 0 || isFailure(disposition);

  const nistSourceCommit =
    typeof vectorSet?.nistSourceCommit === "string" &&
    vectorSet.nistSourceCommit.trim()
      ? vectorSet.nistSourceCommit
      : "—";

  return (
    <article className={`diagnostic-report ${overallFailed ? "failed" : "passed"}`}>
      <header className={`diagnostic-report-header ${overallFailed ? "failed" : "passed"}`}>
        <div>
          <p className="report-section-kicker">NCCU ACVP Server</p>
          <h2>Cryptographic Diagnostic Report</h2>
          <p>Detailed engineering diagnostics for ACVP validation results</p>
        </div>

        <div className={`report-overall ${overallFailed ? "failed" : "passed"}`}>
          <span>Overall result</span>
          <strong>{overallFailed ? "FAILED" : "PASSED"}</strong>
          <small>Vector disposition: {disposition}</small>
        </div>
      </header>

      <p className="report-disclaimer">
        This report records diagnostic results produced by the local NCCU ACVP Server.
        It is not a NIST/CAVP validation certificate.
      </p>

      <section className="diagnostic-summary">
        <h3>Diagnostic summary</h3>
        <dl className="report-metadata">
          <Metadata label="Diagnostic report ID" value={reportId} />
          <Metadata label="Report generated at" value={formatDateTime(reportGeneratedAt)} />
          <Metadata label="Test session ID" value={session.testSessionId} />
          <Metadata label="Vector set ID" value={String(vectorSetId)} />
          <Metadata label="Session label" value={session.label ?? "—"} />
          <Metadata label="Algorithm" value={vectorSet?.algorithm ?? session.algorithm ?? "—"} />
          <Metadata label="Revision" value={vectorSet?.revision ?? session.revision ?? "—"} />
          <Metadata label="Mode" value={vectorSet?.mode ?? session.mode ?? "—"} />
          <Metadata
            label="Parameter set"
            value={parameterSets.length > 0 ? parameterSets.join(", ") : "—"}
          />
          <Metadata
            label="Test type"
            value={testTypes.length > 0 ? testTypes.join(", ") : "—"}
          />
          <Metadata
            label="Sample vector set"
            value={
              sampleVectorSet === undefined
                ? "—"
                : sampleVectorSet
                  ? "Yes"
                  : "No"
            }
          />
          <Metadata label="Session status" value={session.status ?? "—"} />
          <Metadata label="Vector status" value={vectorSet?.status ?? "—"} />
          <Metadata
            label="Validation backend"
            value={session.executionBackend ?? "—"}
          />
          <Metadata
            label="Workflow policy"
            value={session.workflowPolicy ?? "—"}
          />
          <Metadata
            label="Validated at"
            value={formatDateTime(vectorSet?.validatedAt)}
          />
          <Metadata
            label="Publishable"
            value={
              session.publishable === undefined
                ? "—"
                : session.publishable
                  ? "Yes"
                  : "No"
            }
          />
          <Metadata label="IUT response file" value={responseFileName || "—"} />
          <Metadata label="IUT response SHA-256" value={responseSha256 || "—"} />
          <Metadata label="Total test cases" value={String(tests.length)} />
          <Metadata label="Failed test cases" value={String(failedTests.length)} />
          <Metadata
            label="Session vector sets"
            value={String(sessionResults?.results.length ?? session.vectorSetCount)}
          />
          <Metadata label="Backend server version" value={serverVersion?.serverVersion ?? "—"} />
          <Metadata label="Frontend version" value={__APP_VERSION__} />
          <Metadata label="Git commit" value={__GIT_COMMIT__} />
          <Metadata label="NIST GenVal source commit" value={nistSourceCommit} />
          <Metadata
            label="Provider"
            value={
              vectorSet?.providerName ??
              vectorSet?.provider ??
              session.providerName ??
              session.provider ??
              "—"
            }
          />
        </dl>
      </section>

      <section className="diagnostic-failures" style={{ display: failedTests.length === 0 ? "none" : undefined }}>
        <div className="report-section-heading">
          <div>
            <p className="report-section-kicker">Failure diagnostics</p>
            <h3>Failed test cases</h3>
          </div>
          <span className={`report-status ${failedTests.length > 0 ? "failed" : "passed"}`}>
            {failedTests.length}
          </span>
        </div>

        {failedTests.length === 0 ? (
          <p className="report-no-data">
            No failed test cases were returned for this vector set.
          </p>
        ) : (
          Array.from(failedTestGroups.values()).sort((a, b) => Number(a.tgId ?? Number.MAX_SAFE_INTEGER) - Number(b.tgId ?? Number.MAX_SAFE_INTEGER)).map((group) => (
            <section
              className="diagnostic-group"
              key={`tg-${String(group.tgId ?? "unknown")}`}
            >
              <header className="diagnostic-group-header">
                <div className="diagnostic-group-identity">
                  <span>Test group</span>
                  <strong>TG {String(group.tgId ?? "—")}</strong>
                </div>

                <span className="diagnostic-group-count">
                  {group.tests.length} failed test
                  {group.tests.length === 1 ? " case" : " cases"}
                </span>
              </header>

              {group.parameterSet || group.testType ? (
                <div className="diagnostic-group-context">
                  <span>
                    <strong>Parameter Set:</strong> {group.parameterSet ?? "—"}
                  </span>
                  <span>
                    <strong>Test Type:</strong> {group.testType ?? "—"}
                  </span>
                </div>
              ) : null}

              <div className="diagnostic-case-table">
                <div className="diagnostic-case-table-header">
                  <span>TC ID</span>
                  <span>Result</span>
                  <span>Validation reason</span>
                </div>

                {group.tests.map((test, index) => (
                  <article
                    className="diagnostic-case-row"
                    key={`${String(test.tcId)}-${index}`}
                  >
                    <div className="diagnostic-case-row-main">
                      <strong className="diagnostic-tc-id">
                        TC {String(test.tcId ?? "—")}
                      </strong>

                      <span className="report-status failed">
                        {test.result ?? "FAIL"}
                      </span>

                      <span className="diagnostic-case-reason">
                        {test.reason ?? "—"}
                      </span>
                    </div>

                    {hasDiagnosticComparison(test) ? (
                      <div className="diagnostic-comparison">
                        <DiagnosticValue title="Expected" value={test.expected} />
                        <DiagnosticValue title="Provided" value={test.provided} />
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            </section>
          ))
        )}      </section>
    </article>
  );
}

function buildTestGroupMap(
  vectorSetView: NormalizedVectorSetView | null
): Map<string, number | string> {
  const result = new Map<string, number | string>();

  for (const group of vectorSetView?.prompt.testGroups ?? []) {
    for (const testCase of group.tests) {
      result.set(String(testCase.tcId), group.tgId);
    }
  }

  return result;
}

function resolveTgId(
  test: AcvpStrictVectorSetResultTest,
  tgIdByTcId: Map<string, number | string>
): number | string | undefined {
  if (test.tgId !== undefined) {
    return test.tgId;
  }

  if (test.tcId === undefined) {
    return undefined;
  }

  return tgIdByTcId.get(String(test.tcId));
}

function hasDiagnosticComparison(
  test: AcvpStrictVectorSetResultTest
): boolean {
  return test.expected !== undefined || test.provided !== undefined;
}

function DiagnosticValue({
  title,
  value
}: {
  title: string;
  value: unknown;
}) {
  return (
    <div className="diagnostic-value">
      <h4>{title}</h4>
      <pre>{formatJson(value)}</pre>
    </div>
  );
}

function Metadata({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function isFailure(value: unknown): boolean {
  if (typeof value !== "string") {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return normalized === "fail" || normalized === "failed";
}

function formatJson(value: unknown): string {
  if (value === undefined || value === null) {
    return "Not provided.";
  }

  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.trim().length > 0
      )
    )
  );
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
