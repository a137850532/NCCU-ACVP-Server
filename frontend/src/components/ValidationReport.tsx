import type {
  AcvpServerVersion,
  AcvpSessionDetail,
  AcvpVectorSetSummary,
  NormalizedSessionResultsView,
  NormalizedVectorSetResultView,
  NormalizedVectorSetView
} from "../types";

interface ValidationReportProps {
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

type Outcome = "passed" | "failed" | "other";

export default function ValidationReport({
  session,
  vectorSet,
  vectorSetView,
  responseFileName,
  reportGeneratedAt,
  vectorResult,
  sessionResults
}: ValidationReportProps) {
  if (!session || (!vectorResult && !sessionResults)) {
    return (
      <div className="report-empty">
        <strong>No validation report available</strong>
        <span>Submit an IUT response and refresh the validation results.</span>
      </div>
    );
  }

  const tests = vectorResult?.tests ?? [];
  const passedCount = tests.filter(
    (test) => classifyOutcome(test.result) === "passed"
  ).length;
  const failedCount = tests.filter(
    (test) => classifyOutcome(test.result) === "failed"
  ).length;

  const dispositionOutcome = classifyOutcome(vectorResult?.disposition);
  const overallPassed = failedCount === 0 && dispositionOutcome === "passed";

  const overallLabel = overallPassed ? "PASSED" : "FAILED";
  const disposition = vectorResult?.disposition ?? "unreceived";
  const vectorSetId =
    vectorSet?.vsId ?? vectorSet?.vectorSetId ?? "unknown";

  const parameterSets = uniqueStrings(
    (vectorSetView?.prompt.testGroups ?? []).map(
      (group) => group.parameterSet
    )
  );
  const testTypes = uniqueStrings(
    (vectorSetView?.prompt.testGroups ?? []).map(
      (group) => group.testType
    )
  );

  const reportId =
    `NCCU-ACVP-SUMMARY-${session.testSessionId}-VS${String(vectorSetId)}`;

  return (
    <article
      className={`diagnostic-report summary-report ${
        overallPassed ? "passed" : "failed"
      }`}
    >
      <header
        className={`diagnostic-report-header ${
          overallPassed ? "passed" : "failed"
        }`}
      >
        <div>
          <p className="report-section-kicker">NCCU ACVP Server</p>
          <h2>Cryptographic Validation Summary</h2>
          <p>Concise ACVP conformance validation result</p>
        </div>

        <div className={`report-overall ${overallPassed ? "passed" : "failed"}`}>
          <span>Overall result</span>
          <strong>{overallLabel}</strong>
          <small>Vector disposition: {disposition}</small>
        </div>
      </header>

      <p className="report-disclaimer">
        This report records validation performed by the local NCCU ACVP Server.
        It is not a NIST/CAVP validation certificate.
      </p>

      <section className="diagnostic-summary">
        <h3>Validation summary</h3>

        <dl className="report-metadata">
          <Metadata label="Summary report ID" value={reportId} />
          <Metadata
            label="Report generated at"
            value={formatDateTime(reportGeneratedAt)}
          />
          <Metadata label="Test session ID" value={session.testSessionId} />
          <Metadata label="Vector set ID" value={String(vectorSetId)} />

          <Metadata
            label="Algorithm"
            value={vectorSet?.algorithm ?? session.algorithm ?? "—"}
          />
          <Metadata
            label="Revision"
            value={vectorSet?.revision ?? session.revision ?? "—"}
          />
          <Metadata
            label="Mode"
            value={vectorSet?.mode ?? session.mode ?? "—"}
          />
          <Metadata
            label="Parameter set"
            value={parameterSets.length > 0 ? parameterSets.join(", ") : "—"}
          />
          <Metadata
            label="Test type"
            value={testTypes.length > 0 ? testTypes.join(", ") : "—"}
          />
          <Metadata
            label="IUT response file"
            value={responseFileName || "—"}
          />

          <Metadata label="Total test cases" value={String(tests.length)} />
          <Metadata label="Passed test cases" value={String(passedCount)} />
          <Metadata label="Failed test cases" value={String(failedCount)} />
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
        </dl>
      </section>
    </article>
  );
}

function Metadata({
  label,
  value
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
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

function classifyOutcome(value?: string | null): Outcome {
  const normalized = value?.trim().toLowerCase() ?? "";

  if (
    normalized === "passed" ||
    normalized === "pass" ||
    normalized === "success" ||
    normalized === "valid"
  ) {
    return "passed";
  }

  if (
    normalized === "failed" ||
    normalized === "fail" ||
    normalized === "error" ||
    normalized === "invalid"
  ) {
    return "failed";
  }

  return "other";
}

function formatDateTime(value?: string | null): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}
