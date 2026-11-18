// Server-side client for praxis-api. The token never reaches the browser.

export type Summary = {
  techniques: number;
  covered: number;
  detection_gap: number;
  visibility_gap: number;
  blind_rule: number;
  coverage_pct: number;
  weighted_coverage_pct: number | null;
  visible_pct: number;
  rules: { healthy: number; blind: number; disabled: number };
};

export type GapClass = "covered" | "detection_gap" | "visibility_gap" | "blind_rule";

export type Technique = {
  id: string;
  name: string;
  tactics: string[];
  class: GapClass;
  visibility: number;
  weight: number;
  rules: string[];
};

export type Component = {
  name: string;
  score: number;
  source: string;
  table: string;
  silent: boolean;
  factors: Record<string, boolean>;
  detail: {
    events_14d: number;
    events_24h: number;
    days_with_data: number;
    hosts: number;
    expected_hosts: number;
    host_coverage: number;
    field_population: number;
  };
};

export type Rule = {
  id: string;
  platform: string;
  status: "healthy" | "blind" | "disabled";
  last_status: string | null;
  alerts_30d: number;
  techniques: string[];
};

export type Source = {
  platform: string;
  source: string;
  table: string;
  events_14d: number;
  events_24h: number;
  days_with_data: number;
  hosts: number;
  last_event: string | null;
  mapped: boolean;
};

export type Snapshot = {
  id: number;
  client: string;
  client_name: string;
  sector: string;
  taken_at: string;
  attack_version: string;
  summary: Summary;
  components: Component[];
  sources: Source[];
  rules: Rule[];
  techniques: Technique[];
  top_detection_gaps: Technique[];
  top_visibility_gaps: Technique[];
};

export type FleetRow = {
  client_id: string;
  client_name: string;
  sector: string;
  id: number;
  taken_at: string;
  summary: Summary;
  previous_summary: Summary | null;
};

export type HistoryRow = { id: number; taken_at: string; summary: Summary };

export type Diff = {
  from: string | null;
  to: string;
  changes: { id: string; name: string; from: string; to: string }[];
};

const BASE = process.env.PRAXIS_API_URL ?? "http://localhost:8000";

export async function api<T>(path: string): Promise<T | null> {
  const headers: Record<string, string> = {};
  if (process.env.PRAXIS_API_TOKEN) {
    headers.Authorization = `Bearer ${process.env.PRAXIS_API_TOKEN}`;
  }
  const response = await fetch(`${BASE}${path}`, { headers, cache: "no-store" });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`praxis-api ${path} returned ${response.status}`);
  return (await response.json()) as T;
}

export const CLASS_LABEL: Record<GapClass, string> = {
  covered: "Covered",
  detection_gap: "Detection gap",
  blind_rule: "Blind rule",
  visibility_gap: "Visibility gap",
};

export const CLASS_HELP: Record<GapClass, string> = {
  covered: "Visible, with a healthy rule",
  detection_gap: "Visible, but no rule",
  blind_rule: "Rule deployed, but it cannot see or run",
  visibility_gap: "No telemetry to see it",
};

export const CLASS_COLOUR: Record<GapClass, string> = {
  covered: "var(--color-teal)",
  detection_gap: "var(--color-brass)",
  blind_rule: "var(--color-ember)",
  visibility_gap: "var(--color-unseen)",
};

export function when(iso: string): string {
  return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}
