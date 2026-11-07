package dev.polyjose.gradle;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
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
import org.gradle.api.tasks.Optional;
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
 * <p>An artifact ships one native library per target: the AAR one per Android ABI, the JVM jar
 * one per JNA platform. Its notices file is the script's union file, written by one run with a
 * {@code --target} for each of those targets (feature 0013 F14): every crate compiled into any of
 * the libraries, once, under a {@code Targets:} header (a single target gives the single-target
 * file, {@code Target:}). The artifact is one binary distribution, so the union is exactly the
 * crates compiled into it (ADR 0020 §4; feature 0008 F01, option A, orchestrator ruling
 * 2026-11-07). Nothing is merged or edited here.
 *
 * <p>Fail closed: the task then checks the file it ships against the artifact's targets, with the
 * script run again for each target on its own. It fails, naming them, when the file's header does
 * not name exactly the targets, when a target compiles a crate the file does not list, or when the
 * file lists a crate that no target compiles. The crate sets differ today: {@code
 * armv7-linux-androideabi} has no {@code cpufeatures}; the Linux libraries add {@code
 * linux-raw-sys}, the Windows one {@code windows-link} and {@code windows-sys} (feature 0008 T05).
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

    /**
     * A target the artifact ships a library for, counted with {@link #getTargets()} (the modules
     * set the arm64-v8a target and the host's here). Optional; a target listed in both counts once.
     */
    @Input
    @Optional
    public abstract Property<String> getPrimaryTarget();

    /**
     * Every target the artifact ships a library for. Order and repeats do not matter (the script
     * sorts and deduplicates); together with {@link #getPrimaryTarget()} at least one is needed.
     */
    @Input
    public abstract ListProperty<String> getTargets();

    /** A resource directory that holds {@link #NOTICES_PATH}. */
    @OutputDirectory
    public abstract DirectoryProperty getOutputDir();

    @TaskAction
    public void generate() throws IOException {
        Set<String> targets = new TreeSet<>(getTargets().get());
        if (getPrimaryTarget().isPresent()) {
            targets.add(getPrimaryTarget().get());
        }
        if (targets.isEmpty()) {
            throw new GradleException("thirdPartyNotices: no target: the artifact ships no library");
        }

        File work = getTemporaryDir();
        File notices = run(targets, new File(work, "THIRD-PARTY-NOTICES.txt"));
        Set<String> listed = crates(notices);

        List<String> problems = new ArrayList<>();
        List<String> named = targets(notices);
        if (!named.equals(new ArrayList<>(targets))) {
            Set<String> missing = new TreeSet<>(targets);
            named.forEach(missing::remove);
            Set<String> extra = new TreeSet<>(named);
            extra.removeAll(targets);
            problems.add("the file names the targets " + named + ", the artifact's libraries are for "
                    + targets + (missing.isEmpty() ? "" : "; missing: " + String.join(", ", missing))
                    + (extra.isEmpty() ? "" : "; extra: " + String.join(", ", extra)));
        }
        // Each target on its own, so a crate of one library that the shipped file lacks is named.
        Set<String> compiled = new TreeSet<>();
        for (String target : targets) {
            Set<String> crates = targets.size() == 1
                    ? listed
                    : crates(run(Set.of(target), new File(work, target + ".txt")));
            compiled.addAll(crates);
            Set<String> missing = new TreeSet<>(crates);
            missing.removeAll(listed);
            if (missing.isEmpty()) {
                getLogger().lifecycle("thirdPartyNotices: {} ({} third-party crates) is covered",
                        target, crates.size());
            } else {
                problems.add(target + " compiles crates the notices do not list: " + names(missing));
            }
        }
        Set<String> unused = new TreeSet<>(listed);
        unused.removeAll(compiled);
        if (!unused.isEmpty()) {
            problems.add("the notices list crates no target compiles: " + names(unused));
        }
        if (!problems.isEmpty()) {
            throw new GradleException("thirdPartyNotices: the notices do not cover exactly the "
                    + "libraries of the artifact (ADR 0020 §4):\n  " + String.join("\n  ", problems));
        }

        File outDir = getOutputDir().get().getAsFile();
        fs.delete(spec -> spec.delete(outDir));
        File out = new File(outDir, NOTICES_PATH);
        Files.createDirectories(out.getParentFile().toPath());
        Files.copy(notices.toPath(), out.toPath());
        getLogger().lifecycle("thirdPartyNotices: {} ({} third-party crates) -> {}",
                String.join(", ", targets), listed.size(), NOTICES_PATH);
    }

    /** "name version" of each "name version  license" line, for messages. */
    private static String names(Set<String> crates) {
        List<String> out = new ArrayList<>();
        for (String line : crates) {
            out.add(line.split("  ", 2)[0]);
        }
        return String.join(", ", out);
    }

    /** One run of the script with a {@code --target} for each target, writing {@code out}. */
    private File run(Set<String> targets, File out) {
        List<String> command = new ArrayList<>(List.of(
                "bash", getScript().get().getAsFile().getPath(), "-p", getPackageName().get()));
        for (String target : targets) {
            command.add("--target");
            command.add(target);
        }
        command.add("-o");
        command.add(out.getPath());
        exec.exec(spec -> {
            spec.setWorkingDir(getWorkspace().get().getAsFile());
            spec.commandLine(command);
        });
        return out;
    }

    /**
     * The targets the file names: its {@code Target: <t>} line, or {@code Targets: <t1>, <t2>, ...}
     * (sorted by the script), the header third-party-notices.sh writes before the first rule.
     */
    static List<String> targets(File notices) throws IOException {
        for (String line : Files.readAllLines(notices.toPath(), StandardCharsets.UTF_8)) {
            if (line.equals(RULE)) {
                break;
            }
            if (line.startsWith("Target: ")) {
                return List.of(line.substring("Target: ".length()));
            }
            if (line.startsWith("Targets: ")) {
                return List.of(line.substring("Targets: ".length()).split(", ", -1));
            }
        }
        throw new GradleException("thirdPartyNotices: no \"Target:\" or \"Targets:\" line in " + notices
                + " (has scripts/third-party-notices.sh changed its format?)");
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
