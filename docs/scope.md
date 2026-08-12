# Scope: the attack that arrives on its own

There are two supply-chain attack classes, and they differ in how they reach you.

**The one that arrives on its own.** A package you already depend on gets
hijacked — stolen token, compromised maintainer account — and the malicious
version ships to you on your next install. You did nothing. You made no decision.
Your build breaks, or worse, it does not. This is Shai-Hulud. This is ChainDrop.
`keyv@6.0.0` had 48 clean releases and then gained a preinstall script, and
everyone on `^5` was one `npm install` away from it.

**norte-guard covers this class.** The whole design is a capability delta: what
does this version do that the previous forty did not. A hijack is exactly that
shape, which is why the tool can see it before any advisory exists.

**The one you have to type.** A name registered yesterday that was malicious from
its first version. It does not arrive on its own — someone has to add it to a
`package.json`, or be tricked into adding it. That is typosquatting and
dependency confusion.

**norte-guard does not cover this class, and no amount of calibration will
change that.** It is not a gap in the implementation; it is the thesis. The tool
compares a package against its own history. A name that is seventeen seconds old
has no history to compare against, so there is nothing for the method to work
with. There is no signal that fixes this inside this design — a different design
is needed, which means a different tool.

The evidence is on record. Of the packages npm removed while this collector was
watching, two had been scored before the removal:

| Package | Name age | Size | Score | Gate verdict |
|---|---|---|---|---|
| `prezdentkxheiw@1.0.1` | 6 days | 25 KB | 26 | `INSUFFICIENT_HISTORY` |
| `internallib_v756@1.0.7` | 17 seconds | 1.4 KB | 20 | `INSUFFICIENT_HISTORY` |

Neither had an install script. Neither could have reached the block threshold of
70 — the ceiling for a package of that shape is around 26 — and the score was
beside the point anyway, because under the no-genome regime the gate does not
block whatever the number says. Both are the second class. Both were typed by
someone or nobody: neither would have reached a build that had not asked for it.

(That both observed removals were new packages says something about what the
publish feed carries, not about which class costs more. The feed is dominated by
new names. Hijacks are rarer and far more expensive, which is why they are the
ones worth gating on.)

**Meanwhile the collector archives the second class anyway.** The gate does not
block them, but the watcher captures them under the quarantine policy below —
tiny, new, no repository — which is how a dataset for attacking that class gets
built, if that turns out to be worth doing. Archiving is cheap. Claiming
detection would not be.
