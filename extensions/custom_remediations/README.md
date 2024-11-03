# Custom remediations

Xygeni provides automatic remediation for some of the vulnerabilities found during security scanning. 

The remediation action depends on the kind of security issue:

- For open source vulnerabilities, the action is typically a version bump of the vulnerable dependency, up to the fix version.

- For leaked secrets, the action is typically to revoke the leaked credential, rotate it or deactivate the owing account. 

- For CI/CD and SCM misconfigurations, the typical action will change the configuration in the target system to fix or block the vulnerability. 

- For IaC flaws, a modification in cloud assets configurations in the IaC template will be suggested, often in a pull/merge request so the user may confirm or reject the fix.

Remediations can run at scan time, with --auto-remediation option, or in a guardrail playbook with the `remediate()` function,
that will run on the vulnerabilities matching the guardrail conditions. Alternatively, remediations could be run server-side, in a dashboard UI or using the API `/remediate` endpoint, or in automation workflows when the workflow is triggered.

For more details, please read the [Remediation Actions](https://docs.xygeni.io/introduction-to-xygeni/key-concepts/remediation-actions)

## Quick Start

Imagine that you want to add a remediation for a leaked [Dropbox](https://www.dropbox.com/) access token. 
We will use a Dropbox access token as an example, chosen because Dropbox provides a simple mechanism to revoke leaked tokens.

### Define the remediation action

Search the vendor documentation for potential actions that could be automated. 
Most of the time an API endpoint may be called to revoke / rotate the leaked secret, or deactivate the owning account.
Alternatively, a command-line tool may be available to run the action locally.

Note that often you need credentials with the right permissions to perform actions on access tokens, passwords, API keys, etc.
that belong to other users. In that case the scanner has a [token sources configuration](https://docs.xygeni.io/xygeni-scanner-cli/xygeni-cli-overview/scm-ci-cd-and-container-registry-tokens) to fetch the appropriate credential from the environment or a local file. 

In our example, we found that Dropbox provides a [/auth(token/revoke](https://www.dropbox.com/developers/documentation/http/documentation#auth-token-revoke) endpoint that can be used to revoke the leaked token. 

### Implement the remediation

Create a new [custom_dropbox_token.yml](../custom_remediations/src/main/resources/remediation/secret/custom_dropbox_token.yml). You can follow the [template YAML](../custom_remediations/src/main/resources/remediation/_template.yml_).

We will use the `api( baseUrl, method, path [, token, headers, contentType, queryParams, body]) ` remediation function to invoke the intended Dropbox API endpoint. 

The configuration is as follows:

```yaml
# Custom remediation for leaked Dropbox access tokens
# Use the same id of the detector
id: custom_dropbox_token
issueKind: secret
enabled: yes

# Where the remediation can run. Choose between scan, guardrail, backend, or workflow
# Use scan to run at scan time when the --auto-remediate option is set
on: scan, guardrail
description: Revokes a Dropbox access token using the revoke API.

# The change to do on the issue when it is successfully remediated
# One of set_info (default), decrease_severity, discard, or do_nothing
action: set_info

playbook: |
  // Get the token in clear
  dropbox_token = secret.decrypt(issue);
  require exists(dropbox_token);
  
  // invoke the self-revoke endpoint, authenticating with the leaked token
  api(
    'https://api.dropbox.com/2', 'POST', '/auth/token/revoke', 
    token = dropbox_token, body = 'null' 
  );
```

### Deploy and test the remediation

You may simply copy the remediation playbook into the `conf.custom/remediation/secret` directory. The `mvn install` command in the `extensions/custom_detectors` directory will install all the custom remediations for you.

To run the remediation on a leaked Dropbox access token, you may run the scan on an leaked active Dropbox secret.
In our example, we will run the scan with the `--auto-remediate` option:

```bash
xygeni secrets --auto-remediate --detectors=custom_dropbox_token <file with the leaked secret>
```

TRICK: you may get a temporary Dropbox token by clicking in the [<get access token>](https://www.dropbox.com/developers/documentation/http/documentation#auth-token-revoke) link of the Dropbox API endpoint example.

## Examples

1. Runs api call to revoke a gitlab personal access token:

This remediation revokes a GitLab personal access token using the self-revoke API,
to fix the [GitLab Personal Access Token](https://detectors.xygeni.io/xydocs/secrets/detectors/gitlab_token.html) secret leak.

```yaml
id: gitlab_token
issueKind: secret
# Set 'no' or 'false' to disable this remediation.
enabled: yes

on: scan, guardrail
description: Revokes a GitLab personal token using the self-revoke API.

playbook: |
  token = secret.decrypt(issue);
  require exists(token);
  api(
    'gitlab', 'DELETE', '/personal_access_tokens/self', 
    headers = {'PRIVATE-TOKEN': token} 
  )
```

The two expressions here are `token = secret.decrypt(issue);` (assignment to `token` that calls the `secret.decrypt` built-in to get the clear-text secret for the issue (context object)  and `api('gitlab', 'DELETE', '/personal_access_tokens/self', headers = {'PRIVATE-TOKEN': token} )` (a call to an `api` built-in function, that takes three positional arguments and a named `headers` argument).

2. Revoke or suspend a GitHub App:

This remediation will revoke or suspend a GitHub App, to fix the [GitHub App Permissions](https://detectors.xygeni.io/xydocs/misconfigurations/detectors/app_permissions.html) misconfiguration.

```yaml
id: app_permissions
issueKind: misconfiguration

description: |
  Remove or suspend app installation via api. An alternative is to open the GitHub page 
  for editing the installation, where it can be suspended or uninstalled.

# External inputs (passed by the user or consumer of the playbook)
inputs:
  suspend:
    values: ['suspend', 'remove']
    default: 'suspend'

playbook: |
  repo = issue.location.filepath;
  installation_id = issue.properties.app_id;
  org = scm.organization('github', repo);

  require withToken('github', repo) && exists(installation_id);

  when suspend == 'suspend'
  then {
    return api(
      'github', 'PUT', "/app/installations/${installation_id}/suspended",
      token = token('github', repo)
    );
  }

  when suspend == 'remove'
  then {
    return api(
      'github', 'DELETE', '/app/installations',
      token = token('github', repo)
    );
  }

  // return is optional
  openUrl( "https://github.com/organizations/${org}/settings/installations/${installation_id}" );
```

3. Replace open versions for maven components:

This remediation will replace open versions for maven components with the exact latest version,
for fixing the [Maven Avoid Open Versions](https://detectors.xygeni.io/xydocs/misconfigurations/detectors/avoid_open_versions_maven.html) misconfiguration.


This remediation is configured to run at `backend` or `workflow`.

``` yaml
id: avoid_open_versions_maven
issueKind: misconfiguration

on: backend, workflow

description: |
  Replace open versions for maven components with the exact latest version.

playbook: |
  repo = scm.qualifiedRepo;
  version = issue.properties.version;
  ecosystem = issue.properties.ecosystem;
  descriptor = issue.location.filepath;

  require withToken('github', repo);

  when ecosystem == 'maven'
  then 
    latest = sca.resolveDependency('latest', ecosystem, repo, version);

  when exists( latest )
  then {
    comment = "Replace open ${version} with latest version ${latest}";
    bumpTo = {
      ecosystem: ecosystem, from: version, to: latest,
      repo: repo, file: descriptor,  line: issue.location.beginLine,
      comment: comment
    };
    return sca.versionBump( bumpTo, token = token(scm.kind, repo) );
  
  } else {
    msg = "No latest version found for open ${version} of ${ecosystem} dependency found in ${repo}, file ${descriptor}";
    return message( msg, level = 'info' );
  }
```

## Remediation Playbook Reference

Remediation actions are defined in the [remediation playbook](https://docs.xygeni.io/xygeni-scanner-cli/xygeni-cli-overview/remediation-playbooks). A playbook is a set of instructions that run remediation primitives when certain conditions are met. Custom remediations are configured in YAML files located in the `$XYGENI_DIR/conf.custom/remediation/<scan type>` directories.

The configuration YAML for a remediation is as follows:

```yaml
# Use the id of the detector whose issues this remediation applies to
id: <detector id>

# The type of issue to fix: misconfiguration, suspect_dependency, secret, checkpoint_failed,
#  iac_flaw, suspect_activity, code_tampering, sca_vulnerability, code_vulnerability,
#  malware_evidence
issueKind: <detector issue kind>

description: <description>

# Where the remediation can run. Choose between scan, guardrail, backend, or workflow
# - scan: run at scam time when the --auto-remediate option is set
# - guardrail: run in a guardrail playbook with the remediate() function
# - backend: run the remediation server-side, in a dashboard UI or using the API /remediate endpoint
# - workflow: run the remediation server-side, in a workflow playbook
on: scan, guardrail, backend, workflow

# Set the remediation inputs.
inputs:
  varname:
    description: describe the input
    kind: string|integer|real|bool|list|map
    default: the default value
    options: [] # the allowed values, for string or list items
    min: 0 # minimum value for integer|real
    max: 100 # maximum value for integer|real

# The change to do on the issue when it is successfully remediated
# One of set_info (default), decrease_severity, discard, or do_nothing
action: set_info

playbook: |
  // Your remediation instructions, in the Rectify Playbook language
```

A playbook is a sequence of steps (statements). A **Step** can be one of the following statements:

- **Assignment**: `var = <expr>`, where a variable is assigned the value given by the expression.

- **Require**: `require <expr>`, that will test if the (boolean) expression matches to continue executing the playbook.

- **Return**: `return <expr>`, that will end the playbook with the result given by `expr`.

- **When...Then...Else**: `when <expr> then <then-steps> [else <else-steps>]`, that will evaluate the boolean condition `expr` and then run `then-steps` when true, or `else-steps` when false. The 'else' clause is optional.

- **Expression**: `expr`. The expression is evaluated (which could perform some action), but its value is unused. Expressions can run predefined functions, including remediation primitives, or evaluate logical, relational and arithmetic expressions.

## Language Elements

An expression could be an _assignment_ `var = expr` or a _value expression_. The value of an assignment is the one of the right-side value expression, with the side effect that the value is assigned to the variable at left.

Value for expression depends on the statement where it appears, and could be boolean, string, numeric or even object.

The language is case-sensitive, lower-case oriented.

### Statements

The following are valid statements in the Playbook syntax:

#### when \<condition> then \<statement1> [else \<statement2>]
Conditional execution. `<condition>` is a boolean expression. If true, `<statement1>` runs, otherwise `<statement2>` runs.

The `else` clause is optional. `<statement1>` and `<statement2>` could be blocks of atomic statements.

#### for \<var> in \<expression> do \<statement>
Looping statement. `<expression>` must be a collection/array/map. When a collection or array, each value in it is traversed and assigned to `var`, and `<statement` is executed. When a map, each entry pair (key, value) in the map is assigned to `var`.

If the collection/array/map returned by the expression does not exist or is empty, the loop does nothing. If the value returned by the expression is not a collection/array/map, the loop does nothing.

`<statement>` could be an atomic statement or a block.

An index loop between integers a and b (with b > a) could be simulated using the `range(<low_expr>, <high_expr2>, [<step_expr>])` built-in function.

Note: When running in certain contexts, e.g. at backend, the loop could be restricted to a maximum number of iterations to avoid abuse.

#### require \<condition>;
Evaluates `<condition>` expression as boolean. If false, the playbook terminates.

This statement models a requirement that, when not met, prevents the playbook execution to continue.

#### return \<expression>;
Evaluates `<expression>` and terminates the playbook with the expression value.

#### var = \<expression>;
Assignment: gives variable var the value resulting from evaluating `<expression>`.

#### \<expression>;
Expression statement: Evaluates the expression (which can have side effects, like running an OS command or invoking an API).

Note - _Implicit return rule_:  The value of the last expression statement evaluated will be returned from the playbook, if no explicit terminating return statement is provided.

#### { statement1; ... ; statementN; }
Block statement, a sequence of statements between curly braces. 'Atomic' statements must be terminated with a semicolon (;), but can be grouped in a block.

Block statements are useful for conditional execution and loops.


### Types

The language types are _string_, _numeric_ (integer/long, floating point), _boolean_, _arrays/lists_, _maps_ (unordered collections of key:value entries) and _object_ (structured objects in context, passed as inputs or returned from built-in functions).

### Identifiers

An identifier is a sequence of one or more (ASCII) letters or underscore ('_') followed by zero or more letters, digits or underscores.

### Reserved Words
The statement delimiters `when`, `then`, `else`, `for`, `do`, `require` and `return` are reserved words.

The `and` / `or` / `not` logical operators, the `in` operator, and the literal values `true` / `false` / `null` are also reserved words.

### Literals

* **Boolean**: `true` | `false`.

* **Null**: `null`.

* **Numeric**: integer, long (with l or L suffix), or floating point (IEEE 744, following the same syntax of FP literals in Java). Integers and longs can be encoded in octal with a `0`prefix (except for number 0 itself), binary with `0b` prefix, or hexadecimal with a `0x` prefix. Underscores separating thousands are allowed.

* **Single-quote strings**: Between quote (') characters. No string interpolation.

* **Double-quote strings**: Between double quotes ("). String interpolation using `${expr}` placeholders is expected (in that case, expr cannot contain double quotes).

* **Array literal**: Comma-separated sequence of expressions between square brackets (`[` and `]`). Examples: `[]`, `[1, 2, 3]`, `[a, b(), c.d, [1, 2], cond ? x.a : x.b]`.

* **Map literal**: Comma-separated `key : value` entries between curly braces (`{` and `}`). Key could be an identifier (which represents a literal, not a reference to a value) or a single/double quotes. For dynamic key values use interpolation in double quotes. Examples of valid map literals: `{}`, `{k: 'one'}`, `{"${keyname}": exp1, 'default-key': exp2}`.

### Primary expressions

A primary expression evaluates to a value. It could be a [literal](#Literals), an [identifier](#identifiers) referencing to a variable, a `Name` for a path to a field in a field reference chain, a function call, or an array dereference.

### Function calls

The syntax for **function call** is:

```text
namespace.function_name(exp1, ..., expN, name1 = exp, ...)
```

Where the `namespace.` is a dot-separated names for built-in functions for a particular system, `function_name` is the function name, and zero or more positional arguments, followed by zero or more named arguments `<name> = <expr>`. All arguments, positional and named, are comma-separated.

**Return value**: Function calls could return a value that could be assigned to a variable in an assignment expression, or used as argument in another function call.

The available functions are listed below.


### Logical expressions

* Logical and: `E1 && E2 && ... && En` or `E1 and E2 and ... and En`
* Logical or: `E1 || E2 || ... || En` or `E1 or E2 or ... or En`
* Logical (unary) not: `! e` or `not e`

Each expression is evaluated (left to right) as boolean, until the value of the logical expression could be inferred ('closed-loop'). Of course, `!! E` is the same as `E`, `not not not E` is the same as `not E`, etc.

The `&&` and `and` operators, `||` and `or`, and `!` and `not` are equivalent.

Evaluation is _closed loop_: In `E1 && E2`, E2 is not evaluated if E1 is false (which makes the whole expression false). Also, in `E1 || E2` E2 is not evaluated if E1 is already true (which makes the whole expression true).

Note: When an expression value is `null`, it is considered `false` in a logical context: `null && E1` is always false, `null || null` is false, `! null` is true.

### Relational expressions

* Equality: `E1 == E2`
* Inequality: `E1 != E2` or `E1 <> E2`
* Relational: `E1 < E2`, `E1 <= E2`, `E1 > E2`, `E1 >= E2`

Equality and inequality are defined for any type; relational only for numeric values.

Two strings are equal (after interpolation and escape sequences replaced by their characters) after case-sensitive comparison of the character sequence.

Note: With `null` values, `==` / `<=` / `>=` is true when both null, `!=` is true when one is null and the other is not null, and the rest are false.

### In expressions

To test if a value is contained in a sequence, the `in` operator tells if the left-hand expression is contained in the right-hand expression (which could be an array, collection or map): `v in collection` will return true if v is contained in collection, false otherwise.

### Conversions

An empty, blank or null string, when converted to boolean, is false. Any other is true.

An integer/long number, when converted to boolean, is false when zero, true otherwise.

### Ternary expressions

The `cond ? E1 : E2` ternary expression of Java and c# has the same meaning: `cond` is evaluated as boolean, and when true E1 is evaluated, otherwise E2 is evaluated. The value of the expression is either the value for E1 when `cond` is true, or the value of E2.

Execution is _closed-loop_ (E2 is not evaluated when `cond` is true, neither E1 when `cond` is false).

### Arithmetic

The usual arithmetic operators (+ - * / %) work as expected. `a % b` is the remainder of the integer division between a and b.

Note: The sign `+` / `-` in front of a numeric value is not binary addition or subtraction.

### Operator precedence

The language precedence, lower to higher when read top to bottom:

```
= 
?: 
|| 
&& 
== != 
< <= > >= 
+ -
/ * % 
```

So multiplicative operators "bind the most" their operands, while assignment "bind the least". That means that `a = b * c` is interpreted as `a = (b + c)`.

Note: Parentheses could be inserted to change the precedence of operators. So `(a = b) + c` means 'evaluate b, assign its value to a, then sum it with c for the expression value'.

That means the following equivalences using parentheses for clarification:

* `a.b = a.c + a.d` interpreted as `a.b = (a.c + a.d)`
* `a.b = exists(o) ? b+c : c+d` interpreted as `a.b = (exists(o) ? (b+c) : (c+d))`
* `a + b * c` interpreted as `a + (b * c)`
* `a + b * c == d * e or a + b * c > e and h` interpreted as `((a + (b * c)) == (d * e)) or (((a + b * c) > e) and h)`

## Appendix: Formal Grammar

In EBNF, the grammar of the Rectify Playbook language is as follows:

The grammar of the language is as follows:

```ebnf
playbook := statement* ;

statement := 
  when_statement | for_statement | 
  require_statement | return_statement | 
  block | expression_statement | empty_statement ;
  
when_statement := 'when' expression 'then' statement 'else' statement ;
for_statement := 'for' Identifier 'in' expression 'do' statement ;

require_statement := 'require' expression ';' ;
return_statement := 'return' expression ';' ;  

block := '{' statement* '}' ;
expression_statement := expression ';' ;
empty_statement := ';' ;
```

The grammar of expressions is as follows:
```ebnf
expression := assignment_expression;

assignment_expression := [name '='] ternary_expression;
ternary_expression := conditional_or_expression ['?' expression ':' expression];

conditional_or_expression := conditional_and_expression ('||' conditional_and_expression)* ;
conditional_and_expression := equality_expression ('&&' equality_expression)* ;

equality_expression := relational_expression (equlity_op relational_expression)* ;
equlity_op := '==' | '!=' | '<>' ;
relational_expression := additive_expression [relational_operator additive_expression];
relational_op := '<' | '<=' | '>' | '>=' ;

additive_expression := multiplicative_expression additive_op multiplicative_expression ;
additive_op := '+' | '-' ;
multiplicative_expression := unary_expression (multiplicative_op unary_expression)* ;
multiplicative_op := '*' | '/' | '%' ;

unary_expression := unary_op unary_expression | primary_expression ; 
unary_op := '+' | '-' | '!'

primary_expression := 
  ( literal_expression | '(' expression ')' | name ) # prefix 
  ( array_access | function_call | '.' Identifier)*  # suffixes
;

literal_expression := literal | array_literal | map_literal ;
literal := Integer | Long | Floating_point | String_single | String | True | False | Null ;
array_literal := '[' [expression (',' expression)*] ']' ;
map_literal := '{' [map_entry (',' map_entry)* '}' ;
map_entry := (Identifier | String | String_single)  ':' ternary_expression ;

array_access := '[' expression ']' ;
function_call := Name '(' [ argument (',' argument)* ] ')' ;
argument := [Identifier '='] ternary_expression ;

# Lexical spec
# Whitespace is ignored

Name := Identifier ('.' Identifier) ;
Identifier := [A-Za-z_] ([A-Za-z0-9_])* ;

Integer := <same as java int literals, including hex and binary>;
Long := <same as java long literals, including hex and binary>;
Floating_point := <IEEE 754 external representation, as in Java>

True := 'true';
False := 'false';
Null := 'null';

String := <same as Java, with ${primary_expression} placeholders interpolated>;
String_single := <same as Java literals but with ', no interpolation>
```