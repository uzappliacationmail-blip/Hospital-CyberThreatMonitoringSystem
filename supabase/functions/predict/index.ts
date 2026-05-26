import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

// Simple hash function for password verification
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode("ctms_salt_" + password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Severity from confidence
function severityFromConfidence(conf: number): string {
  if (conf >= 0.95) return "critical";
  if (conf >= 0.85) return "high";
  if (conf >= 0.70) return "medium";
  return "low";
}

// Protocol mapping
const protocolMap: Record<number, string> = {
  0: "tcp",
  1: "udp",
  2: "icmp",
};

Deno.serve(async (req: Request) => {
  // Handle CORS
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 200,
      headers: corsHeaders,
    });
  }

  const url = new URL(req.url);
  const path = url.pathname.replace("/functions/v1/predict", "");

  try {
    // Health check
    if (path === "/health" || path === "") {
      return new Response(
        JSON.stringify({
          status: "ok",
          service: "CTMS Prediction API",
          version: "3.2",
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Predict endpoint
    if (path === "/predict" && req.method === "POST") {
      const body = await req.json();

      // Extract features
      const features = {
        duration: parseFloat(body.duration || 0),
        protocol_type: parseInt(body.protocol_type || 0),
        src_bytes: parseFloat(body.src_bytes || 0),
        dst_bytes: parseFloat(body.dst_bytes || 0),
        flag: parseFloat(body.flag || 0),
        wrong_fragment: parseFloat(body.wrong_fragment || 0),
        urgent: parseFloat(body.urgent || 0),
        hot: parseFloat(body.hot || 0),
        num_failed_logins: parseFloat(body.num_failed_logins || 0),
        root_shell: parseFloat(body.root_shell || 0),
      };

      // Simple heuristic-based prediction
      // In production, you'd load a real ML model
      const start = performance.now();

      let anomalyScore = 0;
      const checks = [
        features.duration < 0.01,
        features.protocol_type === 1,
        features.dst_bytes < 10 && features.src_bytes > 1000,
        features.hot > 20,
        features.num_failed_logins > 2,
        features.root_shell > 0,
        features.wrong_fragment > 0,
        features.urgent > 0,
      ];

      anomalyScore = checks.filter(Boolean).length / checks.length;

      // Add some weighted scoring
      if (features.duration < 0.01 && features.dst_bytes === 0) {
        anomalyScore += 0.3;
      }
      if (features.src_bytes > 10000) {
        anomalyScore += 0.2;
      }

      anomalyScore = Math.min(anomalyScore, 1);

      const isAnomaly = anomalyScore > 0.5;
      const confidence = isAnomaly ? 0.7 + anomalyScore * 0.3 : 0.8 + (1 - anomalyScore) * 0.2;
      const elapsed = performance.now() - start;

      const prediction = isAnomaly ? "anomaly" : "normal";

      return new Response(
        JSON.stringify({
          prediction,
          confidence: Math.round(confidence * 1000) / 1000,
          anomaly_confidence: Math.round(anomalyScore * 1000) / 1000,
          response_ms: Math.round(elapsed * 100) / 100,
          severity: severityFromConfidence(confidence),
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Stats endpoint
    if (path === "/stats" && req.method === "GET") {
      // Return mock stats - in production, query the database
      return new Response(
        JSON.stringify({
          total: 1234,
          normal: 988,
          anomaly: 246,
          threat_rate: 19.9,
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    return new Response(
      JSON.stringify({ error: "Not found" }),
      {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Error:", error);
    return new Response(
      JSON.stringify({ error: error.message }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
