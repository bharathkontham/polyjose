package dev.polyjose.gradle;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.gradle.api.GradleException;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.file.Directory;
import org.gradle.api.provider.ProviderFactory;
import org.gradle.api.publish.maven.MavenPom;

/**
 * {@code polyjose.packaging}: what both published modules share (ADR 0011, ADR 0033 §4).
 *
 * <ul>
 *   <li>group {@code dev.polyjose} and the version of the cargo workspace ({@code [workspace.package]
 *       version}), so the Maven artifacts carry the crate version (ADR 0030 §4: {@code version()});
 *   <li>the {@code thirdPartyNotices} task ({@link ThirdPartyNotices}) with its workspace inputs; the
 *       module sets the targets;
 *   <li>{@link #pom}, the POM metadata both publications use.
 * </ul>
 */
public class PackagingPlugin implements Plugin<Project> {
    public static final String GROUP = "dev.polyjose";
    public static final String REPOSITORY = "https://github.com/bharathkontham/polyjose";

    @Override
    public void apply(Project project) {
        // The polyjose repository root, two levels above this Gradle build (platforms/android).
        File root;
        try {
            root = new File(project.getRootDir(), "../..").getCanonicalFile();
        } catch (IOException e) {
            throw new GradleException("cannot resolve the cargo workspace", e);
        }
        Directory workspace = project.getLayout().getProjectDirectory().dir(root.getPath());
        File manifest = workspace.file("Cargo.toml").getAsFile();
        project.setGroup(GROUP);
        project.setVersion(workspaceVersion(manifest));

        project.getTasks().register("thirdPartyNotices", ThirdPartyNotices.class, task -> {
            task.setGroup("build");
            task.setDescription("Writes " + ThirdPartyNotices.NOTICES_PATH
                    + " with scripts/third-party-notices.sh (ADR 0020 §4).");
            task.getWorkspace().set(workspace);
            task.getScript().set(workspace.file("scripts/third-party-notices.sh"));
            task.getPackageName().convention("polyjose-ffi");
            ProviderFactory providers = project.getProviders();
            task.getBash().convention(providers.gradleProperty("polyjose.bash")
                    .orElse(providers.environmentVariable("POLYJOSE_BASH")));
            task.getCargoInputs().from(
                    workspace.file("Cargo.toml"),
                    workspace.file("Cargo.lock"),
                    workspace.file("LICENSE"),
                    project.fileTree(workspace.dir("scripts/licenses")),
                    project.fileTree(workspace, tree -> {
                        tree.include("crates/*/Cargo.toml", "bindings/*/Cargo.toml");
                    }));
            task.getOutputDir().convention(project.getLayout().getBuildDirectory().dir("generated/notices"));
        });
    }

    /**
     * {@code version = "..."} of the {@code [workspace.package]} table, the version every crate of
     * the workspace inherits.
     */
    static String workspaceVersion(File manifest) {
        Pattern version = Pattern.compile("^version\\s*=\\s*\"([^\"]+)\"$");
        try {
            boolean inTable = false;
            for (String raw : Files.readAllLines(manifest.toPath(), StandardCharsets.UTF_8)) {
                String line = raw.trim();
                if (line.startsWith("[")) {
                    inTable = line.equals("[workspace.package]");
                } else if (inTable) {
                    Matcher m = version.matcher(line);
                    if (m.matches()) {
                        return m.group(1);
                    }
                }
            }
        } catch (IOException e) {
            throw new GradleException("cannot read " + manifest, e);
        }
        throw new GradleException("no version in [workspace.package] of " + manifest);
    }

    /**
     * Whether a signing key is configured for vanniktech's signing (its in-memory key property or
     * Gradle's signing plugin properties). ADR 0033 §4 signs "when a key is present"; vanniktech
     * otherwise requires a signature for every non-SNAPSHOT version, which would fail the
     * build-local publication of feature tasks, which run with no key (Gate 3 publishes).
     */
    public static boolean signingKeyPresent(ProviderFactory providers) {
        return providers.gradleProperty("signingInMemoryKey").isPresent()
                || providers.gradleProperty("signing.keyId").isPresent();
    }

    /**
     * The POM metadata Maven Central requires (name, description, URL, license, developer, SCM),
     * the same for both artifacts apart from name and description. polyjose is MIT licensed (ADR
     * 0015).
     */
    public static void pom(MavenPom pom, String name, String description) {
        pom.getName().set(name);
        pom.getDescription().set(description);
        pom.getUrl().set(REPOSITORY);
        pom.getInceptionYear().set("2026");
        pom.licenses(licenses -> licenses.license(license -> {
            license.getName().set("MIT");
            license.getUrl().set("https://opensource.org/license/mit");
            license.getDistribution().set("repo");
        }));
        pom.developers(developers -> developers.developer(developer -> {
            developer.getId().set("bharathkontham");
            developer.getName().set("bharathkontham");
            developer.getUrl().set("https://github.com/bharathkontham");
        }));
        pom.scm(scm -> {
            scm.getUrl().set(REPOSITORY);
            scm.getConnection().set("scm:git:https://github.com/bharathkontham/polyjose.git");
            scm.getDeveloperConnection().set("scm:git:ssh://git@github.com/bharathkontham/polyjose.git");
        });
    }
}
