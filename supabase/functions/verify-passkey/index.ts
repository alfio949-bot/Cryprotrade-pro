import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import * as argon2 from "https://deno.land/x/argon2@v1.0.0/lib/mod.ts";

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
    const { email, passkey, device_fingerprint } = await req.json();
    if (!email || !passkey) return new Response(JSON.stringify({ error: "Dati mancanti" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { data: user, error } = await supabase.from("users").select("id,email,full_name,passkey_hash,device_fingerprints").eq("email", email.toLowerCase().trim()).single();
    if (error || !user) return new Response(JSON.stringify({ success: false, error: "Utente non trovato" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const valid = await argon2.verify(user.passkey_hash, passkey);
    if (!valid) return new Response(JSON.stringify({ success: false, error: "Passkey non valida" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const fingerprints = user.device_fingerprints || [];
    if (device_fingerprint && !fingerprints.includes(device_fingerprint)) {
      fingerprints.push(device_fingerprint);
      await supabase.from("users").update({ device_fingerprints: fingerprints, last_login: new Date().toISOString() }).eq("id", user.id);
    }
    return new Response(JSON.stringify({ success: true, user: { id: user.id, email: user.email, full_name: user.full_name } }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
