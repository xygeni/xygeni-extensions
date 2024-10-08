package io.xygeni.extensions.custom_detectors.misconfigurations;

import com.depsdoctor.core.model.common.Location;
import com.depsdoctor.core.model.scm.ScmCoordinates;
import com.depsdoctor.core.model.scm.github.GitHubApi;
import com.depsdoctor.core.model.scm.github.GitHubCoordinates;
import com.depsdoctor.core.model.scm.gitlab.GitLabApi;
import com.depsdoctor.core.model.scm.gitlab.GitLabCoordinates;
import com.depsdoctor.depsscanner.services.gitlab.model.GitLabProtectedBranch;
import com.depsdoctor.misc.scanner.config.MiscConfig;
import com.depsdoctor.misc.scanner.config.MiscDetectorConfig;
import com.depsdoctor.misc.scanner.detector.AbstractMiscScmDetector;
import com.depsdoctor.misc.scanner.engine.MiscContext;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * UnreviewedBranch - Example of a misconfiguration rule.
 * <p>
 * Looks for "unreviewed branches" (in the default branch, typically 'main' or 'master', and release branches,
 * typically named 'release/{version}'). "Unreviewed" here means that the branch has a protection rule that
 * enforces that reviews are required for allowing a pull request merge into the target branch.
 *
 * @implNote For illustration purposes only. It supports only gitlab and github.
 *           This is not a trivial rule, but a subset of the official unprotected_branch detector.
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
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

  /** Provides information about branches and their protection rule */
  private static class BranchesProvider {
    private final ScmCoordinates scm;
    private final Pattern relaseBranchesPattern;

    public BranchesProvider(ScmCoordinates scm, String releaseBranchesPattern) {
      this.scm = scm;
      this.relaseBranchesPattern = Pattern.compile(releaseBranchesPattern);
    }

    public Map<String, BranchProtectionInfo> getProtectionsForMainReleaseBranches() {
      Map<String, BranchProtectionInfo> result = new TreeMap<>();

      switch (scm.getKind()) {
        case gitlab:
        case gitlab_enterprise: {
          processBranchProtectionGitlab(result);
          break;
        }
        case github: {
          processBranchProtectionGithub(result);
          break;
        }
        default: {
          // other scm systems are unsupported
        }
      }

      return result;
    }

    /** Uses the GitLab API to get the list of target branches and their protection */
    private void processBranchProtectionGitlab(Map<String, BranchProtectionInfo> result) {
      GitLabApi api = GitLabApi.with((GitLabCoordinates) scm);
      try (var branchesApi = api.branches()) {
        // endpoint /projects/{owner}/{repo}/repository/branches
        var branches = branchesApi.getBranches(); // branches for current repository
        // endpoint /projects/{owner}/{repo}/protected_branches
        var protectedBranches = branchesApi.getProtectedBranches();
        // map keyed by branch name
        Map<String, GitLabProtectedBranch> branchInfo = protectedBranches.stream()
          .collect(Collectors.toMap(GitLabProtectedBranch::getName, bp -> bp));

        for (var branch : branches) {
          // is this the repository default branch, or release branch?
          boolean isDefaultOrRelease =
            branch.isDefaultBranch() ||
            relaseBranchesPattern.matcher(branch.getName()).matches();

          if (isDefaultOrRelease) {
            GitLabProtectedBranch bp = branchInfo.get(branch.getName()); // is protected?
            var pi = new BranchProtectionInfo(); // unprotected
            if(bp != null) {
              pi.isProtected = true;
              pi.minReviews = bp.getApprovalsRequired();
              pi.enforceAdmins = true; // in fact, this is the default
            }
            result.put(branch.getName(), pi);
          }
        }
      }
    }

    /**
     * Uses the GitHub API to get the list of target branches and their protection
     *
     */
    private void processBranchProtectionGithub(Map<String, BranchProtectionInfo> result) {
      GitHubApi api = GitHubApi.with((GitHubCoordinates) scm);
      try (var branchesApi = api.branches(); var repoApi = api.repository(scm.getOwner(), scm.getRepo())) {
        var branches = branchesApi.getBranches(null); // all branches
        String defaultBranch = repoApi.getDefaultBranch();

        for (var branch : branches) {
          // is this the repository default branch, or release branch?
          boolean isDefaultOrRelease =
            defaultBranch.equals(branch.getName()) ||
            relaseBranchesPattern.matcher(branch.getName()).matches();

          if (isDefaultOrRelease) {
            var pi = new BranchProtectionInfo();  // unprotected
            pi.isProtected = branch.isProtected();
            var bp = branch.getProtection();
            if(bp != null) {
              var requiredReviews = bp.getRequiredPullRequestReviews();
              pi.minReviews = requiredReviews != null ? requiredReviews.getRequiredApprovingReviewCount() : 0;
              pi.enforceAdmins = bp.getEnforceAdmins() != null && bp.getEnforceAdmins().isEnabled();
            }
            result.put(branch.getName(), pi);
          }
        }
      }
    }
  }

  /** Bean with info about protection rule for a branch */
  public static class BranchProtectionInfo {
    public boolean isProtected; // if false, no protection rule, which is a misconfiguration
    public int minReviews;
    public boolean enforceAdmins;
  }
}
