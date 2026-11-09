import { createClient, SupabaseClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const isSupabaseConfigured = Boolean(
  supabaseUrl &&
  supabaseAnonKey &&
  !supabaseUrl.includes("your-project") &&
  supabaseUrl.startsWith("http")
);

let clientInstance: SupabaseClient | null = null;

if (isSupabaseConfigured) {
  try {
    clientInstance = createClient(supabaseUrl!, supabaseAnonKey!);
  } catch (err) {
    console.warn("[TrustShield Supabase] Initialization deferred:", err);
  }
}

export const supabase = clientInstance;

export interface SupabaseConfigStatus {
  isConfigured: boolean;
  url: string | null;
  hasAnonKey: boolean;
}

export function getSupabaseStatus(): SupabaseConfigStatus {
  return {
    isConfigured: isSupabaseConfigured,
    url: supabaseUrl || null,
    hasAnonKey: Boolean(supabaseAnonKey && !supabaseAnonKey.includes("your-anon-key")),
  };
}
