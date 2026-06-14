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
  return `pbkdf2:sha512:310000:${btoa(String.fromCharCode(...saltBytes))}:${btoa(String.fromCharCode(...new Uint8Array(derived)))}`;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  
  const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
  const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const BREVO_API_KEY = Deno.env.get("BREVO_API_KEY")!;

  try {
    const { email, full_name, passkey, password_hash } = await req.json();
    if (!email || !passkey) {
      return new Response(JSON.stringify({ error: "Dati mancanti" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const emailNorm = email.toLowerCase().trim();
    const passkeyHash = await hashPasskey(passkey);

    const checkRes = await fetch(
      `${SUPABASE_URL}/rest/v1/users?email=eq.${encodeURIComponent(emailNorm)}&select=id`,
      { headers: { "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`, "apikey": SUPABASE_SERVICE_ROLE_KEY } }
    );
    const existing = await checkRes.json() as Array<{id: string}>;
    if (existing.length > 0) {
      return new Response(JSON.stringify({ error: "Email gia registrata" }), {
        status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

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
    const inserted = await insertRes.json() as Array<{id: string, email: string, full_name: string}>;
    if (!insertRes.ok) throw new Error((inserted as unknown as {message: string}).message || "Errore DB");
    const newUser = Array.isArray(inserted) ? inserted[0] : inserted;

    // Send email via Brevo
    const emailPayload = {
      sender: { name: "CryptoTrade Pro", email: "criptotradepro@gmail.com" },
      to: [{ email: emailNorm, name: full_name || emailNorm.split("@")[0] }],
      subject: "La tua Master Passkey - CryptoTrade Pro",
      htmlContent: `<h2 style="color:#6366f1">CryptoTrade Pro</h2><p>Ciao ${full_name || emailNorm.split("@")[0]},</p><p>Registrazione completata! La tua passkey:</p><h3 style="font-family:monospace;letter-spacing:4px;color:#a78bfa;background:#1e1b4b;padding:16px;border-radius:8px">${passkey}</h3><p style="color:#f59e0b">Conservala in un posto sicuro!</p>`,
    };

    const emailRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(emailPayload),
    });

    const emailBody = await emailRes.json();

    return new Response(JSON.stringify({
      success: true,
      user: { id: newUser.id, email: newUser.email, full_name: newUser.full_name },
      email_sent: emailRes.ok,
      email_status: emailRes.status,
      email_response: emailBody,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
