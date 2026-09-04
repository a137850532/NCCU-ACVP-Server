import { acvpEnvelope, isAcvpEnvelope, unwrapAcvpEnvelope } from "./acvp";
import type {
  AcvpServerVersion,
  AcvpSessionDetail,
  AcvpSessionRegistration,
  AcvpSessionSummary,
  AcvpStrictSessionResultItem,
  AcvpStrictVectorSetResults,
  AcvpVectorSetId,
  AcvpVectorSetPayload,
  AcvpVectorSetSummary,
  JsonValue,
  NormalizedSessionResultsView,
  NormalizedVectorSetResultView,
  NormalizedVectorSetView
} from "./types";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
export const ACCESS_TOKEN_STORAGE_KEY = "nccu-acvp-access-token";

export interface AccessToken {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  expiresAt: string;
}

interface RequestOptions extends RequestInit {
  preserveAcvpEnvelope?: boolean;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly path?: string;
  readonly payload?: unknown;

  constructor(message: string, status: number, payload?: unknown, code?: string, path?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
    this.code = code;
    this.path = path;
  }
}

async function request<T>(path: string, options?: RequestOptions): Promise<T> {
  const payload = await requestMaybeJson<T>(path, options);
  if (payload === undefined) {
    throw new Error("Response did not include a JSON body.");
  }
  return payload;
}

export async function requestJson<T>(path: string, options?: RequestOptions): Promise<T> {
  return request<T>(path, options);
}

export async function requestMaybeJson<T>(
  path: string,
  options?: RequestOptions
): Promise<T | undefined> {
  const { preserveAcvpEnvelope = false, ...requestOptions } = options ?? {};
  const headers = new Headers(requestOptions.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (path !== "/acvp/v1/accessTokens") {
    const accessToken = getStoredAccessToken();
    if (accessToken) {
      headers.set("Authorization", `${accessToken.tokenType} ${accessToken.accessToken}`);
    }
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...requestOptions,
    headers
  });
  const payload = await parseResponsePayload(response);
  if (!response.ok) {
    throw buildApiError(response, payload);
  }
  if (payload === undefined) {
    return undefined;
  }
  return (preserveAcvpEnvelope ? payload : unwrapAcvpEnvelope(payload)) as T;
}

export async function requestNewAccessToken(): Promise<AccessToken> {
  return request<AccessToken>("/acvp/v1/accessTokens", { method: "POST" });
}

export function getStoredAccessToken(): AccessToken | null {
  if (typeof localStorage === "undefined") {
    return null;
  }
  const raw = localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const token = JSON.parse(raw) as Partial<AccessToken>;
    if (
      typeof token.accessToken !== "string" ||
      token.tokenType !== "Bearer" ||
      typeof token.expiresIn !== "number" ||
      typeof token.expiresAt !== "string"
    ) {
      clearStoredAccessToken();
      return null;
    }
    if (Date.parse(token.expiresAt) <= Date.now()) {
      clearStoredAccessToken();
      return null;
    }
    return token as AccessToken;
  } catch {
    clearStoredAccessToken();
    return null;
  }
}

export function storeAccessToken(token: AccessToken): void {
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, JSON.stringify(token));
  }
}

export function clearStoredAccessToken(): void {
  if (typeof localStorage !== "undefined") {
    localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
  }
}

export async function getAcvpServerVersion(): Promise<AcvpServerVersion> {
  return request<AcvpServerVersion>("/acvp/v1/version");
}

export async function listAcvpSessions(status?: string): Promise<AcvpSessionSummary[]> {
  const payload = await request<{ testSessions: AcvpSessionSummary[] }>(
    withQuery("/acvp/v1/testSessions", { status })
  );
  return payload.testSessions;
}

export async function createAcvpSession(
  registration: AcvpSessionRegistration
): Promise<AcvpSessionDetail> {
  return request<AcvpSessionDetail>("/acvp/v1/testSessions", {
    method: "POST",
    body: JSON.stringify(acvpEnvelope(registration))
  });
}

export async function getAcvpSession(sessionId: string): Promise<AcvpSessionDetail> {
  return request<AcvpSessionDetail>(`/acvp/v1/testSessions/${encodeURIComponent(sessionId)}`);
}

export async function getAcvpSessionVectorSets(
  sessionId: string
): Promise<AcvpVectorSetSummary[]> {
  const payload = await request<{ vectorSets: AcvpVectorSetSummary[] }>(
    `/acvp/v1/testSessions/${encodeURIComponent(sessionId)}/vectorSets`
  );
  return payload.vectorSets;
}

export async function getAcvpVectorSetPrompt(
  sessionId: string,
  vsId: AcvpVectorSetId
): Promise<NormalizedVectorSetView> {
  const payload = await requestJson<unknown>(vectorPath(sessionId, vsId), {
    preserveAcvpEnvelope: true
  });
  return normalizeVectorSetPrompt(payload, sessionId, vsId);
}

export async function submitAcvpVectorSetResults(
  sessionId: string,
  vsId: AcvpVectorSetId,
  response: JsonValue
): Promise<NormalizedVectorSetResultView | undefined> {
  if (!isAcvpEnvelope(response) && !isRecord(response)) {
    throw new Error("IUT response JSON must be an object or canonical ACVP envelope.");
  }
  const body = isAcvpEnvelope(response) ? response : acvpEnvelope(response);
  const payload = await requestMaybeJson<unknown>(`${vectorPath(sessionId, vsId)}/results`, {
    method: "POST",
    body: JSON.stringify(body),
    preserveAcvpEnvelope: true
  });
  return payload === undefined ? undefined : normalizeVectorSetResults(payload);
}

export async function getAcvpVectorSetResults(
  sessionId: string,
  vsId: AcvpVectorSetId
): Promise<NormalizedVectorSetResultView> {
  const payload = await requestJson<unknown>(`${vectorPath(sessionId, vsId)}/results`, {
    preserveAcvpEnvelope: true
  });
  return normalizeVectorSetResults(payload);
}

export async function getAcvpSessionResults(
  sessionId: string
): Promise<NormalizedSessionResultsView> {
  const payload = await requestJson<unknown>(
    `/acvp/v1/testSessions/${encodeURIComponent(sessionId)}/results`,
    { preserveAcvpEnvelope: true }
  );
  return normalizeSessionResults(payload);
}

export async function downloadAcvpSessionReportPdf(
  sessionId: string
): Promise<{ blob: Blob; filename: string }> {
  const path = `/acvp/v1/testSessions/${encodeURIComponent(sessionId)}/reports/pdf`;
  const headers = new Headers({ Accept: "application/pdf" });
  const accessToken = getStoredAccessToken();
  if (accessToken) {
    headers.set("Authorization", `${accessToken.tokenType} ${accessToken.accessToken}`);
  }
  const response = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!response.ok) {
    throw buildApiError(response, await parseResponsePayload(response));
  }
  const contentType = response.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/pdf")) {
    throw new Error("Report download did not return a PDF file.");
  }
  return {
    blob: await response.blob(),
    filename:
      attachmentFilename(response.headers.get("Content-Disposition")) ??
      `NCCU-ACVP-${sessionId}-validation-report.pdf`
  };
}

async function parseResponsePayload(response: Response): Promise<unknown | undefined> {
  if (response.status === 204) {
    return undefined;
  }
  const text = await response.text();
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function buildApiError(response: Response, payload: unknown): ApiError {
  const body = unwrapAcvpEnvelope<unknown>(payload);
  const detail = extractErrorDetail(body);
  return new ApiError(
    detail.message || response.statusText,
    response.status,
    payload,
    detail.code,
    detail.path
  );
}

function extractErrorDetail(payload: unknown): { message: string; code?: string; path?: string } {
  if (isRecord(payload)) {
    const error = payload.error;
    if (isRecord(error)) {
      return {
        message: stringValue(error.message) ?? stringValue(error.detail) ?? "Request failed.",
        code: stringValue(error.code),
        path: stringValue(error.path)
      };
    }
    if (typeof payload.detail === "string") {
      return { message: payload.detail };
    }
    const message = stringValue(payload.message);
    if (message) {
      return {
        message,
        code: stringValue(payload.code),
        path: stringValue(payload.path)
      };
    }
  }
  return { message: typeof payload === "string" ? payload : "Request failed." };
}

function vectorPath(sessionId: string, vsId: AcvpVectorSetId): string {
  return `/acvp/v1/testSessions/${encodeURIComponent(sessionId)}/vectorSets/${vsId}`;
}

function withQuery(
  path: string,
  params: Record<string, string | number | boolean | undefined | null>
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      query.set(key, String(value));
    }
  }
  const queryString = query.toString();
  return queryString ? `${path}?${queryString}` : path;
}

function normalizeVectorSetPrompt(
  payload: unknown,
  sessionId: string,
  vsId: AcvpVectorSetId
): NormalizedVectorSetView {
  const body = unwrapAcvpEnvelope<unknown>(payload);
  if (!isVectorSetPayload(body)) {
    throw new Error("Vector set response did not contain an ACVP prompt payload.");
  }
  return {
    vectorSetId: vsId,
    sessionId,
    status: stringValue(body.status),
    prompt: body,
    raw: payload,
    sourceShape: "strict-payload"
  };
}

function normalizeVectorSetResults(payload: unknown): NormalizedVectorSetResultView {
  const body = unwrapAcvpEnvelope<unknown>(payload);
  const strictResults = extractStrictVectorSetResults(body);
  if (!strictResults) {
    throw new Error("Vector set results response did not contain a recognizable result body.");
  }
  return {
    disposition: strictResults.results.disposition,
    tests: strictResults.results.tests,
    raw: payload,
    acvpResults: strictResults,
    sourceShape: "strict-payload",
    status: isRecord(body) ? stringValue(body.status) : undefined
  };
}

function normalizeSessionResults(payload: unknown): NormalizedSessionResultsView {
  const body = unwrapAcvpEnvelope<unknown>(payload);
  if (!isStrictSessionResults(body)) {
    throw new Error("Test session results response did not contain a recognizable result body.");
  }
  return {
    passed: body.passed,
    results: body.results,
    raw: payload,
    sourceShape: "strict-payload"
  };
}

function extractStrictVectorSetResults(payload: unknown): AcvpStrictVectorSetResults | undefined {
  if (!isRecord(payload)) {
    return undefined;
  }
  if (isStrictVectorSetResults(payload)) {
    return payload;
  }
  return isStrictVectorSetResults(payload.acvpResults) ? payload.acvpResults : undefined;
}

function isVectorSetPayload(value: unknown): value is AcvpVectorSetPayload {
  return (
    isRecord(value) &&
    Array.isArray(value.testGroups) &&
    (value.vsId === undefined || typeof value.vsId === "number")
  );
}

function isStrictVectorSetResults(value: unknown): value is AcvpStrictVectorSetResults {
  return (
    isRecord(value) &&
    isRecord(value.results) &&
    typeof value.results.disposition === "string" &&
    Array.isArray(value.results.tests)
  );
}

function isStrictSessionResults(
  value: unknown
): value is { passed: boolean; results: AcvpStrictSessionResultItem[] } {
  return isRecord(value) && typeof value.passed === "boolean" && Array.isArray(value.results);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function attachmentFilename(contentDisposition: string | null): string | undefined {
  if (!contentDisposition) {
    return undefined;
  }
  const match = /filename="?([^";]+)"?/i.exec(contentDisposition);
  return match?.[1];
}
