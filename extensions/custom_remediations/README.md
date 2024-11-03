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

The [Remediation Playbook Reference](RemediationPlaybookReference.md) contains the grammar reference and documentation of the remediation built-in functions available.
