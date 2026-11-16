#!/bin/sh
# Runs the ProVerif models and compares each result with the one that this
# directory's README promises. Needs ProVerif 2.05 or later: set PROVERIF to
# its path, or have "proverif" in PATH. The exit status is 1 if a model gives
# another result, also if a control model unexpectedly proves its property.
cd "$(dirname "$0")" || exit 1
PROVERIF=${PROVERIF:-proverif}
status=0

# expect FILE RESULTS: RESULTS is the sorted list of the distinct RESULT
# lines that ProVerif must print.
expect() {
	file=$1
	want=$2
	got=$(timeout 600 "$PROVERIF" -lib stimmig.pvl "$file" 2>&1 | grep '^RESULT' | sort -u)
	if [ "$got" = "$want" ]; then
		echo "ok:   $file"
	else
		echo "FAIL: $file"
		echo "  wanted:"
		echo "$want" | sed 's/^/    /'
		echo "  got:"
		echo "$got" | sed 's/^/    /'
		status=1
	fi
}

expect privacy.pv 'RESULT Observational equivalence is true.'
expect privacy-noblind.pv 'RESULT Observational equivalence cannot be proved.'
expect privacy-nobinding.pv 'RESULT Observational equivalence is true.'
expect integrity.pv 'RESULT event(Counted(p,vA[])) ==> event(HonestCast(p)) is true.
RESULT event(Counted(p,vB[])) ==> event(HonestCast(p)) is true.
RESULT not attacker_p1(vA[]) is true.
RESULT not attacker_p1(vB[]) is true.'
expect integrity-nobinding.pv 'RESULT event(Counted(p,vA[])) ==> event(HonestCast(p)) is false.
RESULT event(Counted(p,vB[])) ==> event(HonestCast(p)) is false.
RESULT not attacker_p1(vA[]) is true.
RESULT not attacker_p1(vB[]) is true.'
exit $status
