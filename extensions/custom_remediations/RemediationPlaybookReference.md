# Remediation Playbook Reference

Automatic [remediation actions](https://docs.xygeni.io/introduction-to-xygeni/key-concepts/remediation-actions) are defined in a **remediation playbook**: a set of instructions that run remediation primitives when certain conditions are met. Custom remediations are configured in YAML files located in the `$XYGENI_DIR/conf.custom/remediation/<scan type>` directories.

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

## Built-in Functions

The following built-in functions are available in the language:

### Basic functions

| Function                       | Description                                                 | Return type  |
|--------------------------------|-------------------------------------------------------------|--------------|
| exists(value)                  | Checks if an object exists and is not null/empty/blank/zero | boolean      |
| length(o)                      | Returns the length of a string, array, map or file (bytes)  | int          |
| file(path)                     | Returns file from its path                                  | File         |
| message(message, level, args)  | Logs a message to the console                               | <none>       |
| range(start, end, step)        | Returns a range of numbers                                  | array of int |


#### exists(value)

Truth in the playbook language is defined as:
- `true` and `false` literals, as themselves.
- `null` literal and null values are false.
- any non-zero number is true, zero is false.
- an empty or blank string is false, non-blank string is true.
- an empty array or map is false, non-empty array or map is true.

`exists(o)` is true according to the truth rules above on the object `o`.

Examples:
```
exists(null); // false
exists("  "); // blank string, false
exists("x"); // true
exists(0); // zero is non-true, false
exists(42); // true
exists([]); // empty array, false
exists(["", null, 0]); // non-empty array, true
exists({}); // empty map, false
exists({a: 0, b: 1}); // non-empty map, true
```

NOTE: `requires expr` is not a function, but a language statement. Checks if a expression is true (with the same logic as `exists()`) and, when false, terminates the playbook with a "no_issue" status, indicating that the remediation cannot be applied.

#### length(o)

Returns the length of a string, array, map or file.

#### file(path)

Gets the file from path, resolving ~/ to home directory and $VAR to environment variables. If the path is not absolute, 
it will be resolved relative to the scan directory, or the current working directory if no scan directory.

#### message(message, level, args)

Logs a message to the console. 
- `message` can be a string or a `String.format` template (placeholders %s, %d, etc.);
- `level` is the level of the message (debug, info, warn, error). Default: info.;
- `args` is a list or array of arguments to inject into the template.

Examples:
```
message('[%s] %s: %s', 'warn', [issue.severity, issue.kind, issue.explain])

result = api(...);
message('Remediation for %s: %s, %s', args = [issue.issueKind, result.status, result.message]);
```

#### range(start, end, step)

Returns a range of numbers from `start` to `end` with step `step`. Useful for loops.

```
list = ...;
num = 0;
for i in range(0, length(list), 2) {
  num += list[i].count;
}
when num > threshold then { ... }
```


### String functions

| Function                                                  | Description                                                     | Return type     |
|-----------------------------------------------------------|-----------------------------------------------------------------|-----------------|
| matches(text, pattern, case_insensitive, partial)         | Checks if a string matches a regular expression                 | boolean         |
| contains(text, substring, case_insensitive)               | Checks if a string contains a substring                         | boolean         |
| starts_with(text, prefix, case_insensitive)               | Checks if a string starts with a given prefix                   | boolean         |
| ends_with(text, suffix, case_insensitive)                 | Checks if a string ends with a given suffix                     | boolean         |
| cat(input)                                                | Concatenates contents of files                                  | array of string |
| cut(input, indexes, delimiter, output_delimiter, is_chars) | Cuts fields or characters from each line of the input           | array of string |
| grep(input, pattern, case_insensitive, invert, whole_line) | Search in text for lines that match a pattern.                  | array of string |
| sed(input, command)                                       | Runs stream editor command for filtering and transforming text. | array of string |

#### Matches, contains, starts_with, ends_with

String functions operate on an input string (`text`). The `case_insensitive` and `partial` parameters are optional, false by default.

**matches((text, pattern, case_insensitive, partial)** returns true when the text matches the pattern. `pattern` is a regular expression, using the Java regex pattern syntax. See the [Java docs](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/regex/Pattern.html) for more details.

**contains((text, substring, case_insensitive)** returns true when the text contains the substring. **starts_with((text, prefix, case_insensitive)** and **ends_with((text, suffix, case_insensitive)** are similar, except that they test whether the text starts or ends with the prefix or suffix, respectively.

```
# Examples of pattern matching
br_best = 'En un lugar de la Marcha';
matches(br_best, '.* de la Mar.*'); // true
matches(br_best, '.* DE LA MAR.*', true); // true
matches(br_best, 'Marcha$', partial = true); // true

contains(br_best, 'Marcha'); // true
contains(br_best, 'marcha', case_insensitive = true); // true
```

#### cat, cut, grep, sed

**cat(input)** concatenates the contents of the input files as an array of strings. `input` can be a file / path string, or an array of files or path strings. Lines from matching files will be split by newlines.


**cut(input, indexes, delimiter, output_delimiter, is_chars)** 'cuts' fields or characters from each line of the input.
`input` is a file or array of strings to be processed. `indexes` is the array with  indexes (starting at 1) for fields (or characters) to be selected. `delimiter`: the input delimiter for extracting fields (defaults to tab character). outDelimiter: the output delimiter (defaults to the input delimiter). Set `is_chars` to true to cut by characters instead of fields

**grep((input, pattern, case_insensitive, invert, whole_line, fixed_string)** searches in `input` for lines that match the given pattern. `input` could be a file, an array of strings, or a string (lines will be split by newlines). `pattern` is a Java regex pattern. `case_insensitive` forces case-insensitive matching. `invert` inverts the result, so that lines that do _not_ match the pattern are returned. `whole_line` forces whole line matching, not substring matching (the default). `fixed_string` forces pattern to be treated as a literal string.

**sed((input, command)** applies the stream editor command `command` to the `input` string and returns the result (follows the sed Unix command syntax). It is useful for replacing text matching a given pattern with a new value, or for extracting a group from the text.

Examples:

```
# Find lines in the file with hardcoded secret that use the key
file = file(issue.location.filepath);
lines_using_key = grep(file, secret.key, fixed_string = true);

# Change the version of react-dom to 18.3.1
lib_version = 'react-dom: 18.2.0';
when matches(lib_version, 'react-dom: 18.2.\d+') then
  fix_version = sed(lib_version, "s/18.2.\d+/18.3.1/g");
```

### Special functions

| Function                               | Description                                                             | Return type        |
|----------------------------------------|-------------------------------------------------------------------------|--------------------|
| secret.decrypt(issue)                  | Decrypts the secret value for remediation.                              | string             |
| success(message, args, body)           | Terminates the playbook with success.                                   | remediation result |
| error(message, args, body)             | Terminates the playbook with error.                                     | remediation result|
| condition_not_met(message, args, body) | Terminates the playbook with 'condition not met' state.                 | remediation result|
| with_token(type, project)              | Returns true if a token of the given type is available for the project. | boolean            |
| token(type, project)                   | Returns the token of the given type for the project.                    | string             |


#### secret.decrypt

`secret.decrypt(issue)` decrypts the secret value for a secret leak issue for remediation: 
often the value is necessary to invoke a command or remote API endpoint that revokes the secret.

#### success, error, condition_not_met

Functions that return a given RemediationResult. They force the termination of the playbook, acting as implicit return.
Syntax: success(args), error(args), condition_not_met(args), where args = `(message, args, body)`: 
message (required)could be a string or a String.format template (placeholders %s, %d, etc.); 
args is a list or array of arguments to inject into the template;
and body is the body of the result, an arbitrary object.


#### Token handling: with_token, token

Remediation actions often need a high-level access token to perform the action on the target system. Token functions work at the scanner-side remediations to fetch the required token from the registered token sources, typically from environment variables or a local file. 

`token(type, repo)` returns the registered token for the repo, or null if no token, taking the token from sources registered in the `xygeni.yml` configuration file. See [SCM, CI/CD and Container Registry Tokens](https://docs.xygeni.io/xygeni-scanner-cli/xygeni-cli-overview/scm-ci-cd-and-container-registry-tokens) for further details.

`with_token(type, repo)` returns true if the token of the given type is available from the registered token sources.

Example:
```
    do_token = secret.decrypt(issue);
    require exists(do_token);
  
    // use the admin token, if available, to revoke the leaked token
    require with_token('digitalocean', scm.qualifiedRepo);
    api(
        'https://cloud.digitalocean.com', 'POST', '/v1/oauth/revoke', 
        token = token('digitalocean', scm.qualifiedRepo),
        body = "token=${do_token}"
    );
```

### Remediation primitives

| Primitive                                             | Description                                  | Return type        |
|-------------------------------------------------------|----------------------------------------------|--------------------|
| api(<args>)                                           | Sends an API endpoint for remediation.       | remediation result |
| command(<args>)                                       | Invokes a command for remediation.           | remediation result |
| documentation()                                       | Dumps the URL of the mitigation/fix section. | remediation result |
| auth0.rotate_secret(domain, client_id, client_secret) | Rotates an Auth0 client secret.              | remediation result |
| aws.accessKey('delete' / 'disable' )                  | Deletes or disables an AWS access key.       | remediation result |
| cloudflare.remediate(token, action)                   | Revokes a Cloudflare token.                  | remediation result |
| slack.remediate(token)                                | Revokes a Slack token.                       | remediation result |
| sca.version_bump(<args>)                              | Performs a version bump.                    | remediation result |

#### api function

`api(<args>)` sends an API endpoint for remediation. Arguments are:

- baseUrl: the base URL for the API endpoint
- method: the HTTP method
- path: the path for the API endpoint, relative to the base URL.
- token: (optional) the authentication token.
- headers: (optional) the headers for the request, a map of key-value strings.
- contentType: (optional) the content type for the request, defaults to 'application/json'.
- queryParams: (optional) the query parameters for the request, a map of key-value strings.
- body: (optional) the body for the request, a map or list of objects, or a JSON string.

Examples:
```bash
  token = secret.decrypt(issue);
  require exists(token);
  api(
    'gitlab', 'DELETE', '/personal_access_tokens/self', 
    headers = {'PRIVATE-TOKEN': token} 
  );
  
  token_to_revoke = secret.decrypt(issue);
  api(
    artifactory_url, 'DELETE', '/access/api/v1/tokens/revoke', 
    token = token('*.jfrog.io', scm.qualifiedRepo),
    body = { 'token': token_to_revoke } 
  ); 
  
  api(
    'https://api.dropbox.com/2', 'POST', '/auth/token/revoke', 
    token = secret.decrypt(issue), body = 'null' 
  );  
```

#### command function

`command(<args>)` invokes a command for remediation. Arguments are:

- executable: the command to execute. 
- arguments: array of arguments for the command.
- timeout: (optional) the timeout for the command, in milliseconds. Defaults to 30,000 (30 seconds).
- checkExit: (optional) if true, the command will be checked for exit code, with 0 assumed as success. Defaults to true.

Examples:
```bash
# runs `npm token revoke` to revoke a leaked NPM token
command('npm', ['token', 'revoke', token]);

#runs aliyun command to deactivate a leaked access key
command('aliyun', ['ram', 'UpdateAccessKey', '--UserAccessKeyId', issue.secretId, '--Status', 'Inactive']);
```

The following are specific remediators with additional logic for remediation:

#### auth0.rotate_secret

`auth0.rotate_secret(domain, client_id, client_secret)` rotates an Auth0 client secret.

Example:
```bash
  // See $XYGENI_DIR/conf/remediation/secret/auth0_keys.yml
  domain = auth0_host ? auth0_host : issue.secretUrl;
  client_id = issue.secretId;
  client_secret = secret.decrypt(issue);
  
  ret = auth0.rotate_secret(domain, client_id, client_secret);
  
  when ret.success then {
    // Link user to the Auth0 dashnoard to get the renewed client secret
    tenant = ret.body['tenant'];
    client_id = ret.body['client_id'];
    manage_url = "https://manage.auth0.com/dashboard/us/${tenant}/applications/${client_id}/setting";
    return message("Open ${manage_url} to get the new secret and replace the old one.", level = 'warn');
  }
```

#### aws.accessKey('delete' / 'disable' )

`aws.accessKey('delete' / 'disable' )` deletes or disables an AWS access key. The `action` argument must be one of 'delete' or 'disable'.
The implicit issue object must be a secret leak issue, with the AWS Key ID and Key Secret. The remediation will search for the key owner.
This remediation is only available on the scan side.

Example:
```bash
  action = 'delete';
  aws.accessKey(action);
```

#### cloudflare.remediate(token, action)

`cloudflare.remediate(token, action)` revokes a Cloudflare token. `token` is the (required) token to revoke / disable, and `action` is either 'disable' or 'delete' (default is disable).

This method performs remediation on a Cloudflare access token by extracting the token ID, sending an HTTP DELETE/ UPDATE request to the Cloudflare API, and returning a RemediationResult indicating the success or failure of the operation.

The method does the following:

- Extracts the token and action parameters from the provided Call object.
- Fetches the admin token required for authorization.
- Extracts the token ID from the provided token value.
- Sends an HTTP DELETE request to the Cloudflare API to delete the token with the extracted token ID.

Returns a RemediationResult indicating whether the deletion was successful or not.

Example:
```bash
  cloudflare_token = secret.decrypt(issue);
  require cloudflare_token;
  cloudflare.remediate(token, 'delete');
```

#### slack.remediate(token)

`slack.remediate(token)` revokes a Slack token.

This method performs remediation on a Slack token by sending an HTTP DELETE request to the Slack API.

Example:
```bash
  slack_token = secret.decrypt(issue);
  require slack_token;
  slack.remediate('https://slack.com/api', 'GET', '/auth.revoke', token = slack_token);
```

#### sca.version_bump(<args>)

Updates a vulnerable dependency version. It clones the repository and replaces the vulnerable version in the dependency manifest with the new version, commits the change in a fix branch, and finally creates a pull request with the change.

Syntax: sca.version_bump(bumpTo, token) where: 
- bumpTo: The BumpTo object. 
- token: The access token of the target SCM.

The BumpTo map has the following entries: 
- depGroup: The dependency group name. 
- depName: The dependency name. 
- depVersion: The dependency version. 
- from: The original version. 
- to: The new version. 
- files: The files to be modified. 
- baseBranch: The base branch. 
- title: The title of the pull request. 
- link: The link to the vulnerability. 
- repo: The repository URL, or shorthand like "github:owner/ repo". 
- tempdir: The temporary directory for the remediation commit.

Example:
```bash
repo = scm.qualifiedRepo;
ecosystem = scm.kind;
require with_token(ecosystem, repo);

when
    exists(fixedWith) && exists(fixedWith.toVersion)
then {
    version = issue.properties.version;
    descriptor = issue.location.filepath;
    line = issue.location.beginLine;
    // User-friendly ID (for example, CVE)
    vulnerability_id = issue.vulnerability.userId;
    comment = "Bump version ${version} of ${ecosystem} dependency found in ${repo}, file ${descriptor} to fix ${vulnerability_id}";
    
    bumpTo = {
      ecosystem: ecosystem, from: version, to: fixedWith.toVersion,
      repo: repo, file: descriptor,  line: line,
      comment: comment
    };
    
    sca.version_bump( bumpTo, token = token(ecosystem, repo) );
}
```


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