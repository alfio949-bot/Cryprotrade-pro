import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const BREVO_API_KEY = Deno.env.get("BREVO_API_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// PBKDF2-SHA512 nativo Deno — 310.000 iterazioni
async function hashPasskey(passkey: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passkey), "PBKDF2", false, ["deriveBits"]
  );
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: saltBytes, iterations: 310000 },
    keyMaterial, 512
  );
  const saltB64 = btoa(String.fromCharCode(...saltBytes));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(derived)));
  return `pbkdf2:sha512:310000:${saltB64}:${hashB64}`;
}

async function verifyPasskey(passkey: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  if (parts.length !== 5) return false;
  const [, , iters, saltB64, hashB64] = parts;
  const enc = new TextEncoder();
  const saltBytes = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passkey), "PBKDF2", false, ["deriveBits"]
  );
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: saltBytes, iterations: parseInt(iters) },
    keyMaterial, 512
  );
  const newHash = btoa(String.fromCharCode(...new Uint8Array(derived)));
  return newHash === hashB64;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { email, full_name, passkey, password_hash } = await req.json();

    if (!email || !passkey) {
      return new Response(JSON.stringify({ error: "Dati mancanti" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const passkeyHash = await hashPasskey(passkey);

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { data: existingUser } = await supabase
      .from("users")
      .select("id")
      .eq("email", email.toLowerCase().trim())
      .single();

    if (existingUser) {
      return new Response(JSON.stringify({ error: "Email gia registrata" }), {
        status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { data: newUser, error: dbError } = await supabase
      .from("users")
      .insert({
        email: email.toLowerCase().trim(),
        full_name: full_name || "",
        passkey_hash: passkeyHash,
        password_hash: password_hash || "",
        created_at: new Date().toISOString(),
      })
      .select("id, email, full_name")
      .single();

    if (dbError) throw new Error(dbError.message);

    // Invia email con Brevo (funziona con qualsiasi destinatario)
    const emailRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        sender: { name: "CryptoTrade Pro", email: "criptotradepro@gmail.com" },
        to: [{ email: email, name: full_name || email.split("@")[0] }],
        subject: "🔐 La tua Master Passkey — CryptoTrade Pro",
        htmlContent: `
          <!DOCTYPE html>
          <html>
          <head><meta charset="UTF-8"/></head>
          <body style="background:#0a0e1a;color:#fff;font-family:Inter,sans-serif;padding:40px 20px;max-width:520px;margin:0 auto;">
            <div style="text-align:center;margin-bottom:32px;">
              <h1 style="background:linear-gradient(135deg,#6366f1,#a855f7,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:28px;font-weight:800;">
                CryptoTrade Pro
              </h1>
              <p style="color:#9ca3af;font-size:14px;">Institutional Trading Terminal</p>
            </div>
            <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:28px;">
              <p style="color:#d1d5db;font-size:15px;">Ciao <strong>${full_name || email.split("@")[0]}</strong>,</p>
              <p style="color:#9ca3af;font-size:14px;margin-top:8px;">La tua registrazione è avvenuta con successo. Ecco la tua Master Passkey:</p>
              <div style="background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(168,85,247,0.15));border:2px solid rgba(99,102,241,0.5);border-radius:12px;padding:24px;text-align:center;margin:24px 0;">
                <p style="color:#9ca3af;font-size:12px;margin-bottom:8px;letter-spacing:1px;">MASTER PASSKEY</p>
                <div style="font-family:'Courier New',monospace;font-size:28px;font-weight:900;letter-spacing:6px;color:#a78bfa;background:rgba(0,0,0,0.3);padding:14px 24px;border-radius:8px;border:1px solid rgba(99,102,241,0.3);display:inline-block;">
                  ${passkey}
                </div>
              </div>
              <div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:14px;margin-top:16px;">
                <p style="color:#f59e0b;font-size:13px;margin:0;line-height:1.6;">
                  ⚠️ <strong>IMPORTANTE:</strong> Questa passkey è l'unico modo per accedere da nuovi dispositivi.
                  Salvala in un posto sicuro. Non la condividere mai con nessuno.
                </p>
              </div>
            </div>
            <p style="color:#6b7280;font-size:11px;text-align:center;margin-top:24px;">
              CryptoTrade Pro — Institutional Terminal · Email automatica, non rispondere
            </p>
          </body>
          </html>
        `,
      }),
    });

    const emailOk = emailRes.ok;

    return new Response(JSON.stringify({
      success: true,
      user: { id: newUser.id, email: newUser.email, full_name: newUser.full_name },
      email_sent: emailOk,
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
