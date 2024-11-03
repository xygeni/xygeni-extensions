package io.xygeni.extensions.custom_detectors;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TestHelper -
 *
 * @author john.doe
 * @version 01-Jan-1980 (john.doe)
 */
public class TestHelper {
  /** Maven's {@code project.basedir}, the module's directory */
  public static File getModuleBasedir() {
    return getDirectoryFromProperty("project.rootdir");
    //return getDirectoryFromProperty("project.basedir");
  }

  /** Maven's {@code project.rootdir}, the root of DepsDoctor project */
  public static File getProjectRootdir() {
    File basedir = getModuleBasedir();
    if(basedir.isDirectory()) {
      File parent = basedir.getParentFile();
      File masterPom = new File(parent, "pom.xml");
      if(masterPom.exists()) return parent;
    }
    return getDirectoryFromProperty("project.rootdir");
  }

  /** {@code ${project.basedir}/src/test/resources}, the test resources for the module */
  public static File getTestResourcesDir() {
    File dir = new File(getModuleBasedir(), "src/test/resources"); // maven standard dirs
    assertThat(dir).as("%s is not a directory", dir).isDirectory();
    return dir;
  }

  public static File getTestResourcesDir(String path) {
    File dir = new File(getTestResourcesDir(), path);
    assertThat(dir).as("%s is not a directory", dir).isDirectory();
    return dir;
  }

  /** The directory as given by a system property with given name.  */
  public static File getDirectoryFromProperty(String propname) {
    String dir = System.getProperty(propname);
    assertThat(dir)
      .as("%s java property must be passed", propname)
      .isNotBlank();

    File directory = new File(dir);
    assertThat(directory)
      .as("%s is not a directory", dir)
      .isDirectory();

    return directory;
  }

}
