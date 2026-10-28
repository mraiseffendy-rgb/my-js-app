"use strict";

/**
 * KONFIGURASI RANZCHAT
 * --------------------
 * Simpan API key Mistral AI di sini.
 * Dapatkan key gratis di: https://console.mistral.ai/api-keys
 *
 * Free tier Mistral ("Experiment"):
 *   - ~1 Request/detik (RPS) per model
 *   - 500.000 Token/menit (TPM)
 *   - ~1 Miliar Token/bulan
 *
 * Model dipilih: "ministral-3-3b" — model terbaru Mistral (rilis 2026),
 * paling ringan (3B param), latency ~0.66s, sangat cocok untuk moderasi real-time.
 * Alternatif: "mistral-small-latest" (lebih pintar) atau "mistral-medium-latest".
 */

module.exports = {
  // ==== API KEY MISTRAL ====
  // Ganti dengan API key kamu dari https://console.mistral.ai/api-keys
  MISTRAL_API_KEY: "ISI_API_KEY_MISTRAL_KAMU_DI_SINI",

  // ==== MODEL & ENDPOINT ====
  MISTRAL_MODEL: "ministral-3-3b",        // model terbaru & tercepat
  MISTRAL_BASE_URL: "https://api.mistral.ai/v1",
  MISTRAL_TIMEOUT_MS: 15000,              // timeout request ke Mistral

  // ==== RATE LIMIT GUARD ====
  // Free tier ~1 RPS. Beri jeda aman antar request agar tidak 429.
  MISTRAL_MIN_INTERVAL_MS: 1200,          // jeda minimum antar panggilan AI
  MISTRAL_MAX_RETRIES: 3,                 // retry jika kena 429
  MISTRAL_RETRY_BASE_MS: 2000,            // backoff awal saat retry

  // ==== PARAMETER AI ====
  MISTRAL_TEMPERATURE: 0.1,               // rendah = deterministik (bagus untuk klasifikasi)
  MISTRAL_MAX_TOKENS: 300,                // output singkat (JSON/verdict)

  // ==== DEVELOPER ACCOUNT ====
  DEV_USERNAME: "Ranz",
  DEV_PASSWORD: "Ranzkeceffgg"
};