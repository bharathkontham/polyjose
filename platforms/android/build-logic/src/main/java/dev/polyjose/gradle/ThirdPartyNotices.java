package dev.polyjose.gradle;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.FileSystemOperations;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;

/**
 * Writes {@code META-INF/polyjose/THIRD-PARTY-NOTICES.txt} for one artifact (ADR 0020 §4, ADR
 * 0033 §4) by running feature 0013's {@code scripts/third-party-notices.sh}, which is called and
 * never changed here.
 *
 * <p>An artifact ships one native library per target, and the notices file is generated for one
 * of them, {@link #getPrimaryTarget()}. The task generates the file for every target in {@link
 * #getTargets()} as well and fails, naming the crates, when the crate set of another target is not
 * a subset of the primary target's: the shipped file must cover every crate compiled into the
 * artifact. It fails closed and never merges files; a union file would be a deliberate change
 * (feature 0008 T04, lead decision 2026-11-07). The crate sets differ today only by subsets:
 * {@code armv7-linux-androideabi} has no {@code cpufeatures}.
 */
public abstract class ThirdPartyNotices extends DefaultTask {
    /** Where the file lands inside the jar ({@code classes.jar} of the AAR, or the JVM jar). */
    public static final String NOTICES_PATH = "META-INF/polyjose/THIRD-PARTY-NOTICES.txt";

    private static final String RULE = "=".repeat(80);

    private final ExecOperations exec;
    private final FileSystemOperations fs;

    @Inject
    public ThirdPartyNotices(ExecOperations exec, FileSystemOperations fs) {
        this.exec = exec;
        this.fs = fs;
    }

    /** {@code scripts/third-party-notices.sh}. */
    @InputFile
    @PathSensitive(PathSensitivity.RELATIVE)
    public abstract RegularFileProperty getScript();

    /**
     * What the script reads: the workspace manifest and lock file, every member manifest, the
     * standard license texts and polyjose's LICENSE. Crate sources in the registry cache are fixed
     * by the lock file.
     */
    @InputFiles
    @PathSensitive(PathSensitivity.RELATIVE)
    public abstract ConfigurableFileCollection getCargoInputs();

    /** The cargo workspace (the polyjose repository root). */
    @Internal
    public abstract DirectoryProperty getWorkspace();

    /** The workspace package that is the artifact's native library ({@code polyjose-ffi}). */
    @Input
    public abstract Property<String> getPackageName();

    /** The target whose notices file ships. */
    @Input
    public abstract Property<String> getPrimaryTarget();

    /** Every target the artifact ships a library for; the primary one may be listed too. */
    @Input
    public abstract ListProperty<String> getTargets();

    /** A resource directory that holds {@link #NOTICES_PATH}. */
    @OutputDirectory
    public abstract DirectoryProperty getOutputDir();

    @TaskAction
    public void generate() throws IOException {
        String primary = getPrimaryTarget().get();
        Set<String> targets = new LinkedHashSet<>();
        targets.add(primary);
        targets.addAll(getTargets().get());

        File work = getTemporaryDir();
        File primaryFile = run(primary, work);
        Set<String> covered = crates(primaryFile);

        List<String> problems = new ArrayList<>();
        for (String target : targets) {
            if (target.equals(primary)) {
                continue;
            }
            Set<String> crates = crates(run(target, work));
            Set<String> missing = new TreeSet<>(crates);
            missing.removeAll(covered);
            Set<String> extra = new TreeSet<>(covered);
            extra.removeAll(crates);
            if (!missing.isEmpty()) {
                problems.add(target + " compiles crates the " + primary + " notices do not list: "
                        + String.join(", ", missing));
            } else {
                getLogger().lifecycle("thirdPartyNotices: {} ({} third-party crates) is covered by {}{}",
                        target, crates.size(), primary,
                        extra.isEmpty() ? " (identical)" : " (it lacks " + String.join(", ", extra) + ")");
            }
        }
        if (!problems.isEmpty()) {
            throw new GradleException("thirdPartyNotices: the shipped notices (" + primary
                    + ") do not cover every library of the artifact (ADR 0020 §4):\n  "
                    + String.join("\n  ", problems));
        }

        File outDir = getOutputDir().get().getAsFile();
        fs.delete(spec -> spec.delete(outDir));
        File out = new File(outDir, NOTICES_PATH);
        Files.createDirectories(out.getParentFile().toPath());
        Files.copy(primaryFile.toPath(), out.toPath());
        getLogger().lifecycle("thirdPartyNotices: {} ({} third-party crates) -> {}",
                primary, covered.size(), NOTICES_PATH);
    }

    private File run(String target, File work) {
        File out = new File(work, target + ".txt");
        exec.exec(spec -> {
            spec.setWorkingDir(getWorkspace().get().getAsFile());
            spec.commandLine("bash", getScript().get().getAsFile().getPath(),
                    "-p", getPackageName().get(), "--target", target, "-o", out.getPath());
        });
        return out;
    }

    /**
     * The "name version  license" lines of the "Third-party crates (N)" list that
     * third-party-notices.sh writes after the polyjose section, checked against N so that a change
     * of the script's format fails here instead of comparing nothing.
     */
    static Set<String> crates(File notices) throws IOException {
        List<String> lines = Files.readAllLines(notices.toPath(), StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (!line.startsWith("Third-party crates (") || !line.endsWith(")")) {
                continue;
            }
            int expected = Integer.parseInt(line.substring("Third-party crates (".length(), line.length() - 1));
            if (i + 1 >= lines.size() || !lines.get(i + 1).equals(RULE)) {
                break;
            }
            Set<String> crates = new TreeSet<>();
            for (int j = i + 2; j < lines.size() && !lines.get(j).isEmpty(); j++) {
                crates.add(lines.get(j));
            }
            if (crates.size() != expected) {
                throw new GradleException("thirdPartyNotices: " + notices + " lists " + crates.size()
                        + " crates under \"" + line + "\"");
            }
            return crates;
        }
        throw new GradleException("thirdPartyNotices: no \"Third-party crates (N)\" list in " + notices
                + " (has scripts/third-party-notices.sh changed its format?)");
    }
}
