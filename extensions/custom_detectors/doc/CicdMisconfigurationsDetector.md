# CI/CD Misconfigurations Detector

A **CI/CD misconfiguration** in any element of the software pipeline, like a package manager, a build file, or a CI job, might open the door to attacks targeted at the organization’s DevOps chain.

The [CI/CD misconfigurations Scanner](https://docs.xygeni.io/xygeni-products/software-supply-chain-security-sscs/ci-cd-scanner) is a tool that checks the configuration of the software project under analysis, and reports any misconfiguration currently active for the policy assigned to the project. Detected misconfigurations could be uploaded to the Xygeni platform for consolidation and for enabling response actions.

The CI/CD misconfigurations engine runs detectors that take different inputs:

- The configuration of a development collaboration platform (SCM) like GitLab, GitHub, Azure DevOps or Bitbucket. 
- The configuration of a continuous integration tool (CI/CD) like Jenkins, CircleCI,Travis CI or the ones embedded in SCM platforms.
- Files in the project under analysis, like build files, workflow / pipeline files, dependency manifests, etc.
- Configurations in manifest files from container images.
- Commits in the project under analysis, to detect changes that did not followed standardized practices like commit signing, code reviews, pull/merge requests on certain branches, etc.

There are different base classes for each of these inputs, which you may extend to implement your custom detector.

## SCM misconfiguration detector

The base `AbstractMiscScmDetector` exposes this interface:

```java
  /** Returns true if given scm repository is accepted by detector for processing. */
  boolean accept(ScmCoordinates scmCoordinates);

  /**
   * Called before file processing, to allow the detector to preload data from the SCM or CI/CD system.
   * Invoked at {@code MiscEngine.preprocessScm(ScmCoordinates, MiscContext, List)}
   */
  default void preprocess(ScmCoordinates scmCoordinates, MiscContext ctx) {}

  /**
   * Analyzes SCM, emitting a Misconfiguration when appropriate.
   * Invoked at {@code MiscEngine.processScm(ScmCoordinates, MiscContext, List)}.
   */
  void execute(ScmCoordinates scmCoordinates, MiscContext ctx);
```

## Examples

### UnreviewedBranch

This detector checks if the default and release branches have a protection rule enforcing code reviews.
Code reviews constitute a best practice to make software safer and more robust, to share knowledge, to detect early security vulnerabilities, potential malicious behaviour, and to check compliance with legal and regulatory requirements. 

This rule checks for each repository scanned if there is an appropriate branch protection rule demanding reviews, for the most important branches like the trunk and the release branches.

Implementing a detector needs to use the SCM branch api. In the [UnreviewedBranch.java](../src/main/java/io/xygeni/extensions/custom_detectors/misconfigurations/UnreviewedBranch.java) example provided, two SCMs (GitLab and GitHub) were chosen to illustrate how to implement a multi-SCM detector (your projects perhaps use different SCMs).

```java
public class UnreviewedBranch extends AbstractMiscScmDetector {
  private BranchesProvider branches;
  private boolean enforceAdmins;
  private int minReviews;
  private String releaseBranchesPattern;

  @Override
  public void configure(MiscDetectorConfig cc, MiscConfig miscConfig) {
    var props = cc.getProperties();
    this.enforceAdmins = (boolean)props.getOrDefault("enforceAdmins", false);
    this.minReviews = (int)props.getOrDefault("minReviews", 1);
    this.releaseBranchesPattern = (String)props.getOrDefault("releaseBranchesPattern", "^release/.+$");
  }

  @Override
  public void preprocess(ScmCoordinates scmCoordinates, MiscContext ctx) {
    // if your detector needs to do setup something before the analysis, do it here
  }

  /**
   * This illustrates how to implement a misconfiguration detector for SCM repositories, using the SCM api.
   * Here we use either the gitlab/github branches api, according to the target repository.
   * The query for protection rules is a bit different for each repository, we encapsulate the details in
   * the {@link BranchesProvider} helper class.
   */
  @Override
  public void execute(ScmCoordinates scm, MiscContext ctx) {
    // Fetching protection rules for the default branch and release branches is abstracted here
    BranchesProvider branches = new BranchesProvider(scm, releaseBranchesPattern);
    var protections = branches.getProtectionsForMainReleaseBranches();

    Location repo = location(scm); // misconfiguration at repository

    // This creates a misconfiguration for each branch not matching the requested protection
    // An alternative is to get the list of misconfigured branches and emit a single misconfiguration for all of them
    // Your mileage may vary here.
    for (var e : protections.entrySet()) {
      String branch = e.getKey();
      BranchProtectionInfo protection = e.getValue();
      // check if branch has the appropriate protection
      check(protection, branch, repo, ctx);
    }
  }

  private void check(BranchProtectionInfo protection, String branch, Location repo, MiscContext ctx) {
    // either the target branch is not protected,
    // or protection rule does not match the configured minimum
    if (!protection.isProtected) {
      String explain = "Branch " + branch + " is not protected";
      report(repo, ctx, explain); // emit misconfiguration

    } else {
      var mismatches = new ArrayList<String>();
      if(protection.minReviews < minReviews) {
        String mismatch = minReviews == 1 ? "No review required" : String.format("Minimum number of reviews required: %d, but branch requires only %s", minReviews, protection.minReviews);
        mismatches.add(mismatch);
      }
      if(enforceAdmins && !protection.enforceAdmins) {
        mismatches.add("Administrators can skip code reviews");
      }
      if(!mismatches.isEmpty()) {
        String explain = String.join("; ", mismatches);
        report(repo, ctx, explain); // emit misconfiguration
      }
    }
  }
}
```

The actual interaction with the SCM api is provided by the `BranchesProvider` inner class. See the code of [BranchesProvider](../src/main/java/io/xygeni/extensions/custom_detectors/misconfigurations/UnreviewedBranch.java) for details.

Once the detector is configured, you may create the [configuration YAML](../src/main/resources/misconfigurations/custom_unreviewed_branch.yml) for the detector, and add unit tests and then create 

> [!NOTE]
> Xygeni provides a more comprehensive detector, **Unprotected branch** (_unprotected_branch_), for checking for unprotected branches. You can configure different aspects of a branch protection rule to enforce:
> - Force push must be disabled.
> - Branch delete must be disabled.
> - Settings must also apply to administrators for the branch.
> - Reviews are required for allowing a pull request to merge into a branch.
> - The minimum number of reviews that need to concur for allowing a pull request to merge into a branch.
> - Code owners must review changes done on sensitive code or configuration.
> - Stale review dismissal must be enabled for the branch (need admin permissions).
> - It is required for branches to be up-to-date with the base branch before merging.
>
> In addition, it supports additional SCMs like Bitbucket and Azure DevOps.
