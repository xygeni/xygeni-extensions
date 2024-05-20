#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
RULES_DIR=$SCRIPT_DIR/../dist/rules

technologies=(\
  "ABAP" "ACTIONSCRIPT" "ASP" "ASPNET" "BYTECODE" "C" "CL400" "COBOL" "CPP" "CSHARP" "FOXPRO" "GO" \
  "GROOVY" "HTML" "INFORMIX" "JAVA" "JAVASCRIPT" "JCL" "JSP" "KOTLIN" "NATURAL" "OBJECTIVEC" "ORACLEFORMS" \
  "OTHER" "PERL" "PHP" "PLSQL" "POWERSCRIPT" "PYTHON" "RPG" "RPG4" "RUBY" "SCALA" "SQL" "SQLSCRIPT" "SWIFT" \
  "TRANSACTSQL" "VB6" "VBNET" "XML" \
)

mkdir -p "${RULES_DIR}"

printf "Generating export rules "

for tech in "${technologies[@]}"
do
  printf "."
  sed "s/{LANG}/$tech/g" "${SCRIPT_DIR}/CUS.ANY.EXT.Export.rule.xml" > "${RULES_DIR}/CUS.$tech.EXT.Export.rule.xml"
  sleep 0.01
done

printf " OK\n"
