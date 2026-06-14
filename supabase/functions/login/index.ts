import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { email, password, device_fingerprint } = await req.json();
    if (!email || !password) return new Response(JSON.stringify({ error: "Dati mancanti" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const emailNorm = email.toLowerCase().trim();
    const { data: user, error } = await supabase.from("users").select("id,email,full_name,password_hash,device_fingerprints").eq("email", emailNorm).single();
    if (error || !user) return new Response(JSON.stringify({ error: "Credenziali non valide" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const data2 = new TextEncoder().encode(password + emailNorm);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data2);
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (hashHex !== user.password_hash) return new Response(JSON.stringify({ error: "Credenziali non valide" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const fingerprints = user.device_fingerprints || [];
    const isKnownDevice = device_fingerprint && fingerprints.includes(device_fingerprint);
    if (!isKnownDevice && fingerprints.length > 0) {
      return new Response(JSON.stringify({ error: "Nuovo dispositivo rilevato. Inserisci la tua Master Passkey.", new_device: true }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (device_fingerprint && !fingerprints.includes(device_fingerprint)) fingerprints.push(device_fingerprint);
    await supabase.from("users").update({ last_login: new Date().toISOString(), device_fingerprints: fingerprints }).eq("id", user.id);
    return new Response(JSON.stringify({ success: true, user: { id: user.id, email: user.email, full_name: user.full_name } }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
