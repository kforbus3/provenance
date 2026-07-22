import { api } from "./client";

// Brokered database access: register database targets and run SQL through Fleet,
// which reaches the database via the jump host with a vaulted credential injected.

export interface Database {
  id: string;
  name: string;
  engine: string; // postgres
  address: string;
  port: number;
  databaseName: string;
  credentialId?: string;
  credentialName?: string;
  description: string;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
}

export interface DatabaseInput {
  name: string;
  engine: string;
  address: string;
  port: number;
  databaseName: string;
  credentialId?: string | null;
  description: string;
}

export interface QueryResult {
  columns: string[];
  rows: string[][];
  rowCount: number;
  command: string; // e.g. "SELECT 5"
  truncated: boolean;
  document?: string; // JSON result for document engines (MongoDB)
}

export async function listDatabases(): Promise<Database[]> {
  const { data } = await api.get<{ databases: Database[] }>("/api/v1/databases");
  return data.databases ?? [];
}

export async function createDatabase(input: DatabaseInput): Promise<Database> {
  const { data } = await api.post<Database>("/api/v1/databases", input);
  return data;
}

export async function updateDatabase(id: string, input: DatabaseInput): Promise<Database> {
  const { data } = await api.put<Database>(`/api/v1/databases/${id}`, input);
  return data;
}

export async function deleteDatabase(id: string): Promise<void> {
  await api.delete(`/api/v1/databases/${id}`);
}

// runQuery executes one SQL statement against the database through the broker. The
// backend injects the vaulted credential and audits the statement.
export async function runQuery(id: string, sql: string): Promise<QueryResult> {
  const { data } = await api.post<QueryResult>(`/api/v1/databases/${id}/query`, { sql });
  return data;
}
