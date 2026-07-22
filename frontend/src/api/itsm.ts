import { api } from "./client";

// ITSM integration (ServiceNow / Jira): open a change ticket for each access approval.
export interface ITSMConfig {
  provider: string; // "servicenow" | "jira" | ""
  baseUrl: string;
  user: string;
  project: string;
  enabled: boolean;
  hasToken: boolean; // the token itself is never returned
}

export interface ITSMInput {
  provider: string;
  baseUrl: string;
  user: string;
  project: string;
  enabled: boolean;
  token?: string; // blank keeps the stored token
}

export async function getITSM(): Promise<ITSMConfig> {
  const { data } = await api.get<ITSMConfig>("/api/v1/itsm/config");
  return data;
}

export async function saveITSM(input: ITSMInput): Promise<ITSMConfig> {
  const { data } = await api.put<ITSMConfig>("/api/v1/itsm/config", input);
  return data;
}

export async function testITSM(): Promise<void> {
  await api.post("/api/v1/itsm/test");
}
