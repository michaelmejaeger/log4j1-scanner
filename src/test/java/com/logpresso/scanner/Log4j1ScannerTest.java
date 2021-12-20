package com.logpresso.scanner;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.Iterator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class Log4j1ScannerTest {

	/**
	 * Total number of test files.
	 */
        private static final int NUM_FILES_TOTAL = 7;

        /**
         * Number of test files that have been already mitigated.
         */
        private static final int NUM_FILES_MITIGATED = 1;
        
        /**
         * Number of test files that are vulnerable.
         */
        private static final int NUM_FILES_VULNERABLE = 4;
        
        /**
         * Number of test files that are potentially vulnerable.
         */
        private static final int NUM_FILES_POTENTIALLY_VULNERABLE = 2;
        
        /**
         * Directory where the test files are stored.
         */
	private static final String ARCHIVES_DIRECTORY = "src/test/resources/archives";
	
	final static Path ARCHIVES_PATH = Paths.get(ARCHIVES_DIRECTORY);
	private Path workingDir;

	/**
	 * Create a temporary working directory and copy all test archives there.
	 */
	@Before
	public void createWorkingCopyOfArchives() throws IOException {
		this.workingDir = Files.createTempDirectory(Log4j1ScannerTest.class.getSimpleName());
		for (Iterator<Path> iter = Files.list(ARCHIVES_PATH).iterator(); iter.hasNext();) {
			Path archive = iter.next();
			Files.copy(archive, Paths.get(this.workingDir.toString(), archive.getFileName().toString()));
		}
	}

	/**
	 * Remove temporary working directory with all contents.
	 */
	@After
	public void removeWorkingCopyOfArchives() throws IOException {
		Files.walk(this.workingDir) //
		.map(Path::toFile) //
		.sorted(Comparator.reverseOrder()) //
		.forEach(File::delete);
	}

	@Test
	public void show_usage() throws IOException {
		Log4j1Scanner scanner0 = new Log4j1Scanner();
		scanner0.run(new String[] {});
		assertEquals(0, scanner0.getVulnerableFileCount());
		assertEquals(0, scanner0.getPotentiallyVulnerableFileCount());
	}
	
	@Test
	public void fix_with_backup() throws IOException {
		Log4j1Scanner scanner1 = new Log4j1Scanner();
		scanner1.run(new String[] { "--force-fix", "--keep-backup", this.workingDir.toString() });
		assertEquals(NUM_FILES_TOTAL * 1l, scanner1.getScanFileCount());
		assertEquals(NUM_FILES_MITIGATED, scanner1.getMitigatedFileCount());
		assertEquals(NUM_FILES_VULNERABLE, scanner1.getVulnerableFileCount());
		assertEquals(NUM_FILES_POTENTIALLY_VULNERABLE, scanner1.getPotentiallyVulnerableFileCount());
		assertEquals(NUM_FILES_VULNERABLE, scanner1.getFixedFileCount());
		Log4j1Scanner scanner2 = new Log4j1Scanner();
		scanner2.run(new String[] { this.workingDir.toString() });
		assertEquals(1l * (NUM_FILES_TOTAL + NUM_FILES_VULNERABLE), scanner2.getScanFileCount());
		assertEquals(NUM_FILES_VULNERABLE + NUM_FILES_MITIGATED, scanner2.getMitigatedFileCount());
		assertEquals(NUM_FILES_POTENTIALLY_VULNERABLE, scanner2.getPotentiallyVulnerableFileCount());
		assertEquals(0, scanner2.getVulnerableFileCount());
	}

	@Test
	public void fix_without_backup() throws IOException {
		Log4j1Scanner scanner1 = new Log4j1Scanner();
		scanner1.run(new String[] { "--force-fix", this.workingDir.toString() });
		assertEquals(NUM_FILES_TOTAL * 1l, scanner1.getScanFileCount());
		assertEquals(NUM_FILES_MITIGATED, scanner1.getMitigatedFileCount());
		assertEquals(NUM_FILES_VULNERABLE, scanner1.getVulnerableFileCount());
		assertEquals(NUM_FILES_POTENTIALLY_VULNERABLE, scanner1.getPotentiallyVulnerableFileCount());
		assertEquals(NUM_FILES_VULNERABLE, scanner1.getFixedFileCount());
		Log4j1Scanner scanner2 = new Log4j1Scanner();
		scanner2.run(new String[] { this.workingDir.toString() });
		assertEquals(NUM_FILES_TOTAL * 1l, scanner2.getScanFileCount());
		assertEquals(NUM_FILES_VULNERABLE + NUM_FILES_MITIGATED, scanner2.getMitigatedFileCount());
		assertEquals(NUM_FILES_POTENTIALLY_VULNERABLE, scanner2.getPotentiallyVulnerableFileCount());
		assertEquals(0, scanner2.getVulnerableFileCount());
	}

	@Test
	public void fix_potentially_vulnerable_without_backup() throws IOException {
		Log4j1Scanner scanner1 = new Log4j1Scanner();
		scanner1.run(new String[] { "--force-fix", "--fix-potentially-vulnerable", this.workingDir.toString() });
		assertEquals(NUM_FILES_TOTAL * 1l, scanner1.getScanFileCount());
		assertEquals(NUM_FILES_MITIGATED, scanner1.getMitigatedFileCount());
		assertEquals(NUM_FILES_VULNERABLE, scanner1.getVulnerableFileCount());
		assertEquals(NUM_FILES_POTENTIALLY_VULNERABLE, scanner1.getPotentiallyVulnerableFileCount());
		assertEquals(NUM_FILES_VULNERABLE + NUM_FILES_POTENTIALLY_VULNERABLE, scanner1.getFixedFileCount());
		Log4j1Scanner scanner2 = new Log4j1Scanner();
		scanner2.run(new String[] { this.workingDir.toString() });
		assertEquals(NUM_FILES_TOTAL * 1l, scanner2.getScanFileCount());
		assertEquals(NUM_FILES_VULNERABLE + NUM_FILES_MITIGATED, scanner2.getMitigatedFileCount());
		assertEquals(0, scanner2.getPotentiallyVulnerableFileCount());
		assertEquals(0, scanner2.getVulnerableFileCount());
	}

}
