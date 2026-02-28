export type PairStartResponse = {
  code: string;
  expiresInMs: number;
  verifyUrl: string;
};

export type PairFinishResponse =
  | { status: "PENDING" }
  | {
      status: "CONFIRMED";
      deviceToken: string;
      userId: string;
      userSigningKeyId?: string;
      userSigningPublicKey?: string;
      deviceGateway?: {
        mtlsRequired?: boolean;
        wsUrl?: string;
        serverCertFingerprint?: string;
      };
    };

export async function startPairing(apiBase: string, deviceId: string, platform: string, version: string, deviceSigningPublicKey?: string, deviceTlsFingerprint?: string) {
  const res = await fetch(`${apiBase}/devices/pair/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId, platform, version, deviceSigningPublicKey, deviceTlsFingerprint }),
  });
  if (!res.ok) throw new Error(`Pair start failed: ${res.status}`);
  return (await res.json()) as PairStartResponse;
}

export async function finishPairing(apiBase: string, deviceId: string, code: string) {
  const res = await fetch(`${apiBase}/devices/pair/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId, code }),
  });
  if (!res.ok && res.status !== 202) throw new Error(`Pair finish failed: ${res.status}`);
  return (await res.json()) as PairFinishResponse;
}
