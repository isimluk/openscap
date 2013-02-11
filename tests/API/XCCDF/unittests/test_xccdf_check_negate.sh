#!/bin/bash

set -e
set -o pipefail

result=`mktemp`
stderr=`mktemp`

$OSCAP xccdf eval --results $result $srcdir/test_xccdf_check_negate.xccdf.xml 2> $stderr

echo "Stderr file = $stderr"
echo "Result file = $result"
[ -f $stderr ]; [ ! -s $stderr ]; rm $stderr

$OSCAP xccdf validate-xml $result

[ $($XPATH $result 'count(//complex-check)') == "0" ]

assert_exists() { [ $($XPATH $result 'count('"$2"')') == "$1" ]; }
assert_exists 1 '//Rule/check[@negate="true"]'
assert_exists 1 '//rule-result/check[@negate="true"]'
assert_exists 1 '//rule-result[@idref="xccdf_moc.elpmaxe.www_rule_1"]/result[text()="pass"]'
rm $result
