// The publisher unit assumes accounts are independent. This one is not.
//
// A5 declares `publisher` its primary unit for a reason that is correct as far
// as it goes: a capture is not an independent event because one operator can
// republish 149 times, and a package is not one because one operator can publish
// five names in four minutes. The account was the level at which members looked
// like separate decisions.
//
// They are not, and the corpus contains a demonstration. `ferrousdev`, `wokorc`
// and `corssdev` share the identical 9-key package.json field order, which over
// 10,192 distinct package names in this store is used by exactly those three
// accounts and by nobody else, and they run the same two-tier structure four
// times inside 28.6 hours: publish a primitive with no dependencies, then
// publish a `sui-*` package that imports it.
//
//   bcs-core   <- sui-gql-core       ferrousdev  2026-08-17 10:52
//   leb128x    <- sui-move-rpc       ferrousdev  2026-08-17 13:35
//   ulebkit    <- sui-move-graphql   wokorc      2026-08-17 17:05
//   sui-move-gql                     corssdev    2026-08-18 15:30
//
// A5 counted the first two as two of its eight independent events. Every
// interval it printed at the publisher unit is therefore narrower than the truth
// by one degree of freedom, in the same direction as the capture unit's error
// and for the same reason: a unit whose members are not independent.
//
// WHAT THIS MODULE IS AND IS NOT. It is a declared table of links that have been
// demonstrated, with the evidence written beside each one. It is NOT a detector:
// nothing here infers a new link at runtime, because a similarity judgement over
// a corpus this size finds pairs by chance and a wrong link merges two real
// events into one, which shrinks n in a way no interval would show.

export type OperatorEvidence =
  | 'content-signature'
  | 'counter-sequence'
  | 'shared-token'

export interface OperatorLink {
  // A stable id for the operator. Deliberately not one of the account names: the
  // accounts are peers and picking one to stand for the rest reads as though the
  // others were secondary, which is not established.
  operator: string
  accounts: string[]
  evidence: OperatorEvidence[]
  // Written out so a reader can disagree with the link without reconstructing it.
  // A merge that turns out to be wrong costs a degree of freedom the analysis
  // cannot get back, so the bar is what would convince someone who did not want
  // to believe it.
  because: string
  establishedAt: string
}

// Frozen, and short on purpose. Two entries, both established by measurement and
// both stated with the number that makes them checkable.
export const KNOWN_OPERATORS: OperatorLink[] = [
  {
    operator: 'sui-primitive-operator',
    accounts: ['ferrousdev', 'wokorc', 'corssdev'],
    evidence: ['content-signature'],
    because:
      'Identical package.json field order — name, version, description, main, scripts, keywords, ' +
      'author, license, files — which 10,192 distinct package names in this corpus reduce to 7,505 ' +
      'signatures, of which this one is used by these three accounts and no others. Reinforced by ' +
      'the same two-tier structure four times in 28.6 hours: a dependency-free primitive, then a ' +
      'sui-* package importing it (bcs-core <- sui-gql-core, leb128x <- sui-move-rpc, ' +
      'ulebkit <- sui-move-graphql, then sui-move-gql). Six of the packages are confirmed_malicious ' +
      'by npm takedown; sui-move-gql was never taken down and is labelled from this link alone.',
    establishedAt: '2026-08-21',
  },
  {
    operator: 'th-sequence-operator',
    accounts: ['node-mini-tools', 'pkg-utils-lab', 'tiny-js-helpers'],
    evidence: ['counter-sequence', 'content-signature'],
    because:
      'One counter ascending across all three accounts — 37, 38, 39, 41, 44, 45, 47, 48, 49, 51, ' +
      '53, 54, 56, 57, 59, 61, 63 — with 17 of 21 adjacent-by-number pairs landing on a different ' +
      'account, spaced about 58 seconds apart. The numbered-sequence detector fires once in 12,327 ' +
      'names and this is the once. Independently, 22 of their 27 packages share one package.json ' +
      'field order that no other publisher in the corpus uses. None is confirmed_malicious, so this ' +
      'link is recorded and contributes no case to A5.',
    establishedAt: '2026-08-21',
  },
]

// The operator an account belongs to, or the account itself when no link is
// declared. Falling back to the account rather than to null is what makes this
// safe to use as a grouping key: an unlinked account is its own operator, which
// is the assumption the publisher unit already makes, so the operator unit can
// never be COARSER than the publisher unit by accident.
export function operatorOf(publisher: string | null | undefined): string | null {
  if (publisher === null || publisher === undefined) return null
  const link = KNOWN_OPERATORS.find(o => o.accounts.includes(publisher))
  return link ? link.operator : publisher
}

export function linkFor(publisher: string): OperatorLink | null {
  return KNOWN_OPERATORS.find(o => o.accounts.includes(publisher)) ?? null
}

// How many accounts the declared links collapse, over a set of publishers.
// Printed beside any publisher-unit count so the two are never read as the same
// number.
export interface Collapse {
  accounts: number
  operators: number
  merged: Array<{ operator: string; accounts: string[] }>
}

export function collapse(publishers: Array<string | null>): Collapse {
  const accounts = new Set<string>()
  for (const p of publishers) if (p) accounts.add(p)

  const byOperator = new Map<string, Set<string>>()
  for (const account of accounts) {
    const key = operatorOf(account)!
    const at = byOperator.get(key) ?? new Set<string>()
    at.add(account)
    byOperator.set(key, at)
  }

  return {
    accounts: accounts.size,
    operators: byOperator.size,
    merged: [...byOperator.entries()]
      .filter(([, set]) => set.size > 1)
      .map(([operator, set]) => ({ operator, accounts: [...set].sort() })),
  }
}
