export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = Record<string, JsonValue>;

export type AcvpVersion = "1.0";

export interface AcvpServerVersion {
  acvVersion: string;
  apiVersion: string;
  serverName: string;
  serverVersion?: string;
  workflowPolicy?: string;
  executionBackend?: string;
  nistReferences?: JsonValue[];
  [key: string]: JsonValue | undefined;
}
export type AcvpEnvelope<T> = [{ acvVersion: AcvpVersion }, T];
export type AcvpVectorSetId = number;

export interface AcvpTestCase {
  tcId: number | string;
  [key: string]: JsonValue;
}

export interface AcvpTestGroup {
  tgId: number | string;
  testType?: string;
  parameterSet?: string;
  tests: AcvpTestCase[];
  [key: string]: JsonValue | AcvpTestCase[] | undefined;
}

export interface AcvpVectorSet {
  vsId?: AcvpVectorSetId;
  algorithm?: string;
  mode?: string;
  revision?: string;
  testGroups: AcvpTestGroup[];
  [key: string]: JsonValue | AcvpTestGroup[] | undefined;
}

export type FipsVersionId = "FIPS203" | "FIPS204";
export type AcvpRevision =
  | "FIPS203"
  | "FIPS204"
  | "FIPS204-tr1";
export type CapabilityMode = "keyGen" | "sigGen" | "sigVer" | "encapDecap";
export type MlKemFunction =
  | "encapsulation"
  | "decapsulation"
  | "encapsulationKeyCheck"
  | "decapsulationKeyCheck";
export type MldsaParameterSet = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";
export type MlKemParameterSet = "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
export type AcvpParameterSet = MldsaParameterSet | MlKemParameterSet;

export interface CapabilityModeConfig {
  id: CapabilityMode;
  label: string;
  enabled: boolean;
  revisions: AcvpRevision[];
  defaultRevision: AcvpRevision;
}

export interface FipsVersionConfig {
  id: FipsVersionId;
  label: string;
  algorithm: "ML-DSA" | "ML-KEM";
  revision: AcvpRevision;
  enabled: boolean;
  status: "available" | "in-development";
  disabledReason?: string;
  modes: CapabilityModeConfig[];
  defaultModes: CapabilityMode[];
  parameterSets: AcvpParameterSet[];
  defaultParameterSets: AcvpParameterSet[];
  functions?: MlKemFunction[];
  defaultFunctions?: MlKemFunction[];
  defaultHashAlgs?: string[];
}

export interface AcvpSessionRegistration {
  algorithms: JsonObject[];
  label?: string;
  autoGenerateVectorSets?: boolean;
  testsPerGroup?: number;
  campaignSeed?: string;
}

export interface AcvpSessionSummary {
  testSessionId: string;
  status: string;
  label?: string | null;
  vectorSetIds: AcvpVectorSetId[];
  vsIds?: AcvpVectorSetId[];
  vectorSetUrls: string[];
  vectorSetCount: number;
  downloadedVectorSetCount?: number;
  submittedVectorSetCount?: number;
  validatedVectorSetCount?: number;
  failedVectorSetCount?: number;
  pendingVectorSetCount?: number;
  mode?: string | null;
  algorithm?: string | null;
  revision?: string | null;
  testGroupCount?: number;
  testCaseCount?: number;
  workflowPolicy?: "strict";
  executionBackend?: "nist-genval";
  passed?: boolean;
  publishable?: boolean;
  provider?: string | null;
  providerName?: string | null;
  [key: string]: unknown;
}

export interface AcvpSessionDetail extends AcvpSessionSummary {
  vectorSets?: AcvpVectorSetSummary[];
  stateHistory?: JsonValue[];
  negotiatedCapabilities?: JsonValue;
}

export interface AcvpVectorSetSummary {
  vectorSetId: AcvpVectorSetId;
  vsId: AcvpVectorSetId;
  testSessionId: string;
  status: string;
  url: string;
  mode?: string | null;
  algorithm?: string | null;
  revision?: string | null;
  testGroupCount?: number;
  testCaseCount?: number;
  provider?: string | null;
  providerName?: string | null;
  downloadedAt?: string | null;
  submittedAt?: string | null;
  validatedAt?: string | null;
  [key: string]: unknown;
}

export type AcvpVectorSetPayload = AcvpVectorSet;

export interface AcvpStrictVectorSetResultTest {
  tgId?: number | string;
  tcId?: number | string;
  result?: string;
  reason?: string;
  expected?: JsonValue | null;
  provided?: JsonValue | null;
  [key: string]: JsonValue | undefined;
}

export interface AcvpStrictVectorSetResultsBody {
  vsId?: AcvpVectorSetId;
  disposition: string;
  tests: AcvpStrictVectorSetResultTest[];
  [key: string]: JsonValue | AcvpStrictVectorSetResultTest[] | undefined;
}

export interface AcvpStrictVectorSetResults {
  results: AcvpStrictVectorSetResultsBody;
}

export interface AcvpStrictSessionResultItem {
  vectorSetUrl: string;
  status: string;
  disposition?: string;
  [key: string]: JsonValue | undefined;
}

export type NormalizedSourceShape = "strict-payload";

export interface NormalizedVectorSetView {
  vectorSetId?: AcvpVectorSetId;
  sessionId?: string;
  status?: string;
  prompt: AcvpVectorSetPayload;
  raw: unknown;
  sourceShape: NormalizedSourceShape;
}

export interface NormalizedVectorSetResultView {
  disposition: string;
  tests: AcvpStrictVectorSetResultTest[];
  raw: unknown;
  sourceShape: NormalizedSourceShape;
  status?: string;
  acvpResults?: AcvpStrictVectorSetResults;
}

export interface NormalizedSessionResultsView {
  passed?: boolean;
  results: AcvpStrictSessionResultItem[];
  raw: unknown;
  sourceShape: NormalizedSourceShape;
}
