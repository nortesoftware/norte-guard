// If norte-guard becomes popular, it becomes the target. A tool that reads every
// packument and downloads suspicious tarballs is exactly what an attacker wants
// to compromise, and its blast radius is the whole ecosystem.
//
// The posture that follows from that: never install or execute what it captures,
// keep deltas local, ship a pinned and verifiable binary, and label every capture
// as hostile. The full threat model lives in SECURITY.md.

export interface NgpackSafetyLabel {
  isMalicious: boolean
  maliciousCampaign?: string
  // Literal types, not booleans — a capture must never be able to claim it is
  // safe to install, whatever else it carries.
  safeToInstall: false
  doNotExecute: true
  capturedForResearch: true
}

// Stubbed in v1 so the contract exists at the call site before the mechanism
// does. v2 verifies a Sigstore keyless signature produced by the release
// workflow, with the identity anchored in the release tag rather than in the
// binary that would be checking itself.
export async function verifySelfIntegrity(): Promise<{ ok: boolean; details: string }> {
  return {
    ok: true,
    details: 'Self-integrity check: stub (v1). See SECURITY.md for the Sigstore implementation.',
  }
}
