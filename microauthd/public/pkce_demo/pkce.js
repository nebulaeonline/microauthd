const AUTH_URL = "http://localhost:9040";

document.getElementById("login-btn").onclick = async () => {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const totp = document.getElementById("totp").value;
    const out = document.getElementById("result");

    out.textContent = "Starting PKCE flow...";

    const jti = genRandom(16);
    const codeVerifier = genRandom(64);
    localStorage.setItem("code_verifier", codeVerifier);
    const codeChallenge = await computeS256(codeVerifier);
    const method = "S256";

    // STEP 1: Authorize
    const authRes = await fetch(`${AUTH_URL}/authorize`, {
        method: "POST",
        body: new URLSearchParams({
            client_id: "demo",
            redirect_uri: "http://localhost:9040/pkce_demo/callback.html",
            code_challenge: codeChallenge,
            code_challenge_method: method,
            scope: "openid email",
            nonce: genRandom(12),
            state: genRandom(8),
        }),
    });

    const auth = await authRes.json();
    if ("success" in auth && auth.success === false) {
        // This is an error case
        console.error(auth.message || "Unknown error");
        return;
    }

    const jtiValue = auth.jti;
    const clientId = auth.client_id;
    const redirectUri = auth.redirect_uri;
    const requiresTotp = auth.requires_totp;

    // STEP 2a: Password login
    const pwRes = await fetch(`${AUTH_URL}/login/password`, {
        method: "POST",
        body: new URLSearchParams({
            jti: jtiValue,
            username: username,
            password: password,
            redirect_uri: redirectUri,
        }),
    });

    const pw = await pwRes.json();
    if ("success" in pw && pw.success == false) return showErr(out, "Password login failed", pw);

    // STEP 2b: TOTP (if required)
    if (requiresTotp) {
        document.getElementById("totp-label").style.display = "block";

        if (!totp) return (out.textContent = "TOTP required. Enter code and retry.");

        const totpRes = await fetch(`${AUTH_URL}/login/totp`, {
            method: "POST",
            body: new URLSearchParams({
                jti: jtiValue,
                totp_code: totp,
            }),
        });

        const totpResult = await totpRes.json();
        if (!totpResult.success) return showErr(out, "TOTP failed", totpResult);
    }

    // Step 2c: Before Finalize, store our code & challenge info because
    // finalize will redirect to the specified redirect uri where we will
    // fetch the token
    localStorage.setItem("code_verifier", codeVerifier);
    localStorage.setItem("code_challenge_method", method);
    localStorage.setItem("client_id", clientId);
    localStorage.setItem("redirect_uri", redirectUri);

    // STEP 3: Finalize
    const form = document.createElement("form");
    form.method = "POST";
    form.action = `${AUTH_URL}/login/finalize`;

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "jti";
    input.value = jtiValue;
    form.appendChild(input);

    document.body.appendChild(form);
    form.submit();
};

function showErr(out, label, err) {
    out.textContent = `${label}:\n\n${JSON.stringify(err, null, 2)}`;
}

function genRandom(len) {
    const array = new Uint8Array(len);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function computeS256(verifier) {
    const enc = new TextEncoder().encode(verifier);
    const hash = await crypto.subtle.digest("SHA-256", enc);
    const bytes = Array.from(new Uint8Array(hash));
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
