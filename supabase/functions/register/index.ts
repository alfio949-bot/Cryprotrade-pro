import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const BREVO_API_KEY = Deno.env.get("BREVO_API_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function hashPasskey(passkey: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passkey), "PBKDF2", false, ["deriveBits"]);
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: saltBytes, iterations: 310000 },
    keyMaterial, 512
  );
  const saltB64 = btoa(String.fromCharCode(...saltBytes));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(derived)));
  return `pbkdf2:sha512:310000:${saltB64}:${hashB64}`;
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

    const emailNorm = email.toLowerCase().trim();
    const passkeyHash = await hashPasskey(passkey);

    // Controlla duplicati
    const checkRes = await fetch(
      `${SUPABASE_URL}/rest/v1/users?email=eq.${encodeURIComponent(emailNorm)}&select=id`,
      { headers: { "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, "apikey": SUPABASE_SERVICE_ROLE_KEY } }
    );
    const existing = await checkRes.json();
    if (existing.length > 0) {
      return new Response(JSON.stringify({ error: "Email gia registrata" }), {
        status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Inserisci utente
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation",
      },
      body: JSON.stringify({
        email: emailNorm,
        full_name: full_name || "",
        passkey_hash: passkeyHash,
        password_hash: password_hash || "",
        created_at: new Date().toISOString(),
      })
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(inserted.message || "Errore DB");
    const newUser = Array.isArray(inserted) ? inserted[0] : inserted;

    // Invia email con Brevo — funziona con qualsiasi destinatario
    const emailRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        sender: { name: "CryptoTrade Pro", email: "criptotradepro@gmail.com" },
        to: [{ email: emailNorm, name: full_name || emailNorm.split("@")[0] }],
        subject: "🔐 La tua Master Passkey — CryptoTrade Pro",
        htmlContent: `<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="background:#0a0e1a;color:#fff;font-family:Arial,sans-serif;padding:40px 20px;max-width:520px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:32px;">
    <h1 style="color:#a78bfa;font-size:28px;font-weight:800;margin:0;">CryptoTrade Pro</h1>
    <p style="color:#9ca3af;font-size:14px;margin-top:8px;">Institutional Trading Terminal</p>
  </div>
  <div style="background:#111827;border:1px solid #1f2937;border-radius:16px;padding:28px;">
    <p style="color:#d1d5db;font-size:15px;">Ciao <strong>${full_name || emailNorm.split("@")[0]}</strong>,</p>
    <p style="color:#9ca3af;font-size:14px;">Registrazione completata! Ecco la tua Master Passkey:</p>
    <div style="background:#1e1b4b;border:2px solid #6366f1;border-radius:12px;padding:24px;text-align:center;margin:24px 0;">
      <p style="color:#9ca3af;font-size:12px;margin:0 0 8px 0;letter-spacing:2px;text-transform:uppercase;">Master Passkey</p>
      <div style="font-family:'Courier New',monospace;font-size:26px;font-weight:900;letter-spacing:5px;color:#a78bfa;background:#0f0f23;padding:14px 24px;border-radius:8px;display:inline-block;">
        ${passkey}
      </div>
    </div>
    <div style="background:#451a03;border:1px solid #92400e;border-radius:8px;padding:14px;">
      <p style="color:#fbbf24;font-size:13px;margin:0;line-height:1.6;">
        &#9888;&#65039; <strong>IMPORTANTE:</strong> Questa passkey &egrave; l&apos;unico modo per accedere da nuovi dispositivi. Salvala in un posto sicuro!
      </p>
    </div>
  </div>
  <p style="color:#6b7280;font-size:11px;text-align:center;margin-top:24px;">CryptoTrade Pro &mdash; Email automatica, non rispondere</p>
</body></html>`,
      }),
    });

    const emailData = await emailRes.json().catch(() => ({}));

    return new Response(JSON.stringify({
      success: true,
      user: { id: newUser.id, email: newUser.email, full_name: newUser.full_name },
      email_sent: emailRes.ok,
      email_id: (emailData as Record<string, string>).messageId || null,
    }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
