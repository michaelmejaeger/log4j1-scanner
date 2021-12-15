package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Log4j1Scanner {
	private static final String BANNER = "Logpresso CVE-2021-44228 Vulnerability Scanner 1.5.0 (2021-12-15)";

	public enum Status {
		NOT_VULNERABLE, MITIGATED, POTENTIALLY_VULNERABLE, VULNERABLE;
	}

	private static final String POTENTIALLY_VULNERABLE = "N/A - potentially vulnerable";
	private static final String JNDI_LOOKUP_CLASS_PATH = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
	private static final String LOG4j_CORE_POM_PROPS = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties";
	private static final boolean isWindows = File.separatorChar == '\\';

	// status logging
	private long scanStartTime = 0;
	private long lastStatusLoggingTime = System.currentTimeMillis();
	private long lastStatusLoggingCount = 0;
	private File lastVisitDirectory = null;

	// results
	private long scanDirCount = 0;
	private long scanFileCount = 0;
	private int vulnerableFileCount = 0;
	private int mitigatedFileCount = 0;
	private int fixedFileCount = 0;
	private int potentiallyVulnerableFileCount = 0;

	private Set<File> vulnerableFiles = new LinkedHashSet<File>();

	// options
	private String targetPath;
	private boolean debug = false;
	private boolean trace = false;
	private boolean silent = false;
	private boolean fix = false;
	private boolean force = false;
	private boolean scanZip = false;
	private boolean noSymlink = false;
	private boolean allDrives = false;
	private Set<File> driveLetters = new TreeSet<File>();
	private List<String> excludePaths = new ArrayList<String>();
	private List<String> excludePatterns = new ArrayList<String>();

	public static void main(String[] args) {
		try {
			Log4j1Scanner scanner = new Log4j1Scanner();
			scanner.run(args);
			System.exit(scanner.vulnerableFileCount + scanner.potentiallyVulnerableFileCount);
		} catch (Throwable t) {
			System.out.println("Error: " + t.getMessage());
			System.exit(-1);
		}
	}

	public void run(String[] args) throws IOException {
		if (args.length < 1) {
			pringUsage();
			return;
		}

		parseArguments(args);

		if (fix && !force) {
			try {
				System.out.print("This command will remove JndiLookup.class from log4j2-core binaries. Are you sure [y/N]? ");
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String answer = br.readLine();
				if (!answer.equalsIgnoreCase("y")) {
					System.out.println("interrupted");
					return;
				}
			} catch (Throwable t) {
				System.out.println("error: " + t.getMessage());
				return;
			}
		}

		run();
	}

	private void pringUsage() {
		System.out.println(BANNER);
		System.out.println("Usage: log4j2-scan [--fix] target_path");
		System.out.println("");
		System.out.println("--fix");
		System.out.println("\tBackup original file and remove JndiLookup.class from JAR recursively.");
		System.out.println("--force-fix");
		System.out.println("\tDo not prompt confirmation. Don't use this option unless you know what you are doing.");
		System.out.println("--debug");
		System.out.println("\tPrint exception stacktrace for debugging.");
		System.out.println("--trace");
		System.out.println("\tPrint all directories and files while scanning.");
		System.out.println("--silent");
		System.out.println("\tDo not print anything until scan is completed.");
		System.out.println("--scan-zip");
		System.out.println("\tScan also .zip extension files. This option may slow down scanning.");
		System.out.println("--no-symlink");
		System.out.println("\tDo not detect symlink as vulnerable file.");
		System.out.println("--exclude [path_prefix]");
		System.out.println("\tExclude specified paths. You can specify multiple --exclude [path_prefix] pairs");
		System.out.println("--exclude-config [file_path]");
		System.out.println("--exclude-pattern [pattern]");
		System.out.println("\tExclude specified paths by pattern. You can specify multiple --exclude-pattern [pattern] pairs (non regex)");
		System.out.println(
				"\tSpecify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.");
		System.out.println("--all-drives");
		System.out.println("\tScan all drives on Windows");
		System.out.println("--drives c,d");
		System.out.println("\tScan specified drives on Windows. Spaces are not allowed here.");
	}

	private void parseArguments(String[] args) throws IOException {
		int i = 0;
		for (; i < args.length; i++) {
			if (args[i].equals("--fix")) {
				fix = true;
			} else if (args[i].equals("--force-fix")) {
				fix = true;
				force = true;
			} else if (args[i].equals("--debug")) {
				debug = true;
			} else if (args[i].equals("--trace")) {
				trace = true;
			} else if (args[i].equals("--silent")) {
				silent = true;
			} else if (args[i].equals("--scan-zip")) {
				scanZip = true;
			} else if (args[i].equals("--no-symlink")) {
				noSymlink = true;
			} else if (args[i].equals("--all-drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--all-drives is supported on Windows only.");

				allDrives = true;
			} else if (args[i].equals("--drives")) {
				if (!isWindows)
					throw new IllegalArgumentException("--drives is supported on Windows only.");

				if (args.length > i + 1) {
					for (String letter : args[i + 1].split(",")) {
						letter = letter.trim().toUpperCase();
						if (letter.length() == 0)
							continue;

						if (letter.length() > 1)
							throw new IllegalArgumentException("Invalid drive letter: " + letter);

						char c = letter.charAt(0);
						if (c < 'A' || c > 'Z')
							throw new IllegalArgumentException("Invalid drive letter: " + letter);

						driveLetters.add(new File(letter + ":\\"));
					}
				} else {
					throw new IllegalArgumentException("Specify drive letters.");
				}

				i++;
			} else if (args[i].equals("--exclude")) {
				if (args.length > i + 1) {
					String path = args[i + 1];
					if (path.startsWith("--")) {
						throw new IllegalArgumentException("Path should not starts with `--`. Specify exclude file path.");
					}

					if (isWindows)
						path = path.toUpperCase();

					excludePaths.add(path);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude file path.");
				}
			} else if (args[i].equals("--exclude-pattern")) {
				if (args.length > i + 1) {
					String pattern = args[i + 1];
					if (pattern.startsWith("--")) {
						throw new IllegalArgumentException("Pattern should not starts with `--`. Specify exclude pattern.");
					}

					if (isWindows)
						pattern = pattern.toUpperCase();

					excludePatterns.add(pattern);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude pattern.");
				}
			} else if (args[i].equals("--exclude-config")) {
				if (args.length > i + 1) {
					String path = args[i + 1];
					if (path.startsWith("--")) {
						throw new IllegalArgumentException("Path should not starts with `--`. Specify exclude file path.");
					}

					File f = new File(path);
					if (!f.exists() || !f.canRead())
						throw new IllegalArgumentException("Cannot read exclude config file: " + f.getAbsolutePath());

					loadExcludePaths(f);
					i++;
				} else {
					throw new IllegalArgumentException("Specify exclude file path.");
				}
			} else {
				if (i == args.length - 1)
					targetPath = args[i];
				else
					throw new IllegalArgumentException("unsupported option: " + args[i]);
			}
		}

		// verify drive letters
		verifyDriveLetters();

		// verify conflict option
		if (allDrives && !driveLetters.isEmpty())
			throw new IllegalArgumentException("Cannot specify both --all-drives and --drives options.");

		if (!allDrives && driveLetters.isEmpty() && targetPath == null)
			throw new IllegalArgumentException("Specify scan target path.");
	}

	private void loadExcludePaths(File f) throws IOException {
		FileInputStream fis = null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "utf-8"));

			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				line = line.trim();

				if (line.startsWith("#"))
					continue;

				if (isWindows)
					line = line.toUpperCase();

				excludePaths.add(line);
			}

		} finally {
			ensureClose(fis);
			ensureClose(br);
		}
	}

	private void verifyDriveLetters() {
		File[] roots = File.listRoots();
		Set<File> availableRoots = new HashSet<File>();
		if (roots != null) {
			for (File root : roots) {
				availableRoots.add(root);
			}
		}

		for (File letter : driveLetters) {
			if (!availableRoots.contains(letter))
				throw new IllegalStateException("Unknown drive: " + letter);
		}
	}

	public void run() {
		scanStartTime = System.currentTimeMillis();
		System.out.println(BANNER);
		try {
			if (allDrives) {
				int i = 0;
				System.out.print("Scanning drives: ");
				for (File drive : File.listRoots()) {
					if (i++ != 0)
						System.out.print(",");
					System.out.print(drive);
				}
				System.out.println("");

				for (File drive : File.listRoots())
					traverse(drive);
			} else if (!driveLetters.isEmpty()) {
				for (File drive : driveLetters)
					traverse(drive);
			} else {
				File f = new File(targetPath);
				System.out.println("Scanning directory: " + f.getAbsolutePath());
				traverse(f);
			}

			if (fix)
				fix(trace);
		} finally {
			long elapsed = System.currentTimeMillis() - scanStartTime;
			System.out.println();
			System.out.println("Scanned " + scanDirCount + " directories and " + scanFileCount + " files");
			System.out.println("Found " + vulnerableFileCount + " vulnerable files");
			System.out.println("Found " + potentiallyVulnerableFileCount + " potentially vulnerable files");
			System.out.println("Found " + mitigatedFileCount + " mitigated files");
			if (fix)
				System.out.println("Fixed " + fixedFileCount + " vulnerable files");

			System.out.printf("Completed in %.2f seconds\n", elapsed / 1000.0);
		}
	}

	private void fix(boolean trace) {
		if (!vulnerableFiles.isEmpty())
			System.out.println("");

		for (File f : vulnerableFiles) {
			File symlinkFile = null;
			String symlinkMsg = "";

			if (isSymlink(f)) {
				try {
					symlinkFile = f;
					f = symlinkFile.getCanonicalFile();
					symlinkMsg = " (from symlink " + symlinkFile.getAbsolutePath() + ")";
				} catch (IOException e) {
					// unreachable (already known symlink)
				}
			}

			if (trace)
				System.out.printf("Patching %s%s%n", f.getAbsolutePath(), symlinkMsg);

			File backupFile = new File(f.getAbsolutePath() + ".bak");

			if (backupFile.exists()) {
				System.out.println("Error: Cannot create backup file. .bak File already exists. Skipping " + f.getAbsolutePath());
				continue;
			}

			if (copyAsIs(f, backupFile)) {
				// keep inode as is for symbolic link
				if (!truncate(f)) {
					System.out.println("Error: Cannot patch locked file " + f.getAbsolutePath());
					continue;
				}

				if (copyExceptJndiLookup(backupFile, f)) {
					fixedFileCount++;

					System.out.printf("Fixed: %s%s%n", f.getAbsolutePath(), symlinkMsg);
				} else {
					// rollback operation
					copyAsIs(backupFile, f);
				}
			}
		}
	}

	private boolean truncate(File f) {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			raf.setLength(0);
			return true;
		} catch (Throwable t) {
			return false;
		} finally {
			ensureClose(raf);
		}
	}

	private boolean copyAsIs(File srcFile, File dstFile) {
		FileInputStream is = null;
		FileOutputStream os = null;

		try {
			is = new FileInputStream(srcFile);
			os = new FileOutputStream(dstFile);

			byte[] buf = new byte[32768];
			while (true) {
				int len = is.read(buf);
				if (len < 0)
					break;

				os.write(buf, 0, len);
			}

			return true;
		} catch (Throwable t) {
			System.out.println("Error: Cannot copy file " + srcFile.getAbsolutePath() + " - " + t.getMessage());
			return false;
		} finally {
			ensureClose(is);
			ensureClose(os);
		}
	}

	private boolean copyExceptJndiLookup(File srcFile, File dstFile) {
		ZipFile srcZipFile = null;
		ZipOutputStream zos = null;

		try {
			srcZipFile = new ZipFile(srcFile);
			zos = new ZipOutputStream(new FileOutputStream(dstFile));
			zos.setMethod(ZipOutputStream.STORED);
			zos.setLevel(Deflater.NO_COMPRESSION);

			Enumeration<?> e = srcZipFile.entries();
			while (e.hasMoreElements()) {
				ZipEntry entry = (ZipEntry) e.nextElement();

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					continue;

				if (entry.isDirectory()) {
					ZipEntry newEntry = new ZipEntry(entry.getName());
					newEntry.setMethod(ZipEntry.STORED);
					newEntry.setCompressedSize(0);
					newEntry.setSize(0);
					newEntry.setCrc(0);

					zos.putNextEntry(newEntry);

					continue;
				}

				copyZipEntry(srcZipFile, entry, zos);
			}

			return true;
		} catch (Throwable t) {
			if (debug)
				t.printStackTrace();

			System.out.println(
					"Error: Cannot fix file (" + t.getMessage() + "). rollback original file " + dstFile.getAbsolutePath());
			return false;
		} finally {
			ensureClose(srcZipFile);
			ensureClose(zos);
		}
	}

	private void copyZipEntry(ZipFile srcZipFile, ZipEntry zipEntry, ZipOutputStream zos) throws IOException {
		InputStream is = null;
		try {
			is = srcZipFile.getInputStream(zipEntry);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			if (isScanTarget(zipEntry.getName())) {
				copyNestedJar(is, bos);
			} else {
				byte[] buf = new byte[32768];
				while (true) {
					int len = is.read(buf);
					if (len < 0)
						break;

					bos.write(buf, 0, len);
				}
			}

			byte[] tempBuf = bos.toByteArray();
			ZipEntry entry = new ZipEntry(zipEntry.getName());
			entry.setMethod(ZipEntry.STORED);
			entry.setCompressedSize(tempBuf.length);
			entry.setSize(tempBuf.length);
			entry.setCrc(computeCrc32(tempBuf));

			zos.putNextEntry(entry);
			transfer(new ByteArrayInputStream(tempBuf), zos);

		} finally {
			ensureClose(is);
		}
	}

	private void transfer(InputStream is, OutputStream os) throws IOException {
		byte[] buf = new byte[32768];
		while (true) {
			int len = is.read(buf);
			if (len < 0)
				break;

			os.write(buf, 0, len);
		}
	}

	private void copyNestedJar(InputStream is, OutputStream os) throws IOException {
		ZipInputStream zis = null;
		ZipOutputStream zos = null;
		try {
			zis = new ZipInputStream(new DummyInputStream(is));
			zos = new ZipOutputStream(os);

			while (true) {
				ZipEntry zipEntry = zis.getNextEntry();
				if (zipEntry == null)
					break;

				if (zipEntry.getName().equals(JNDI_LOOKUP_CLASS_PATH))
					continue;

				if (zipEntry.isDirectory()) {
					ZipEntry entry = new ZipEntry(zipEntry.getName());
					zos.putNextEntry(entry);
					continue;
				}

				// fix recursively
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				if (isScanTarget(zipEntry.getName())) {
					copyNestedJar(zis, bos);
				} else {
					byte[] buf = new byte[32768];
					while (true) {
						int len = zis.read(buf);
						if (len < 0)
							break;

						bos.write(buf, 0, len);
					}
				}

				byte[] outputBuf = bos.toByteArray();
				ZipEntry entry = new ZipEntry(zipEntry.getName());

				zos.putNextEntry(entry);

				transfer(new ByteArrayInputStream(outputBuf), zos);
			}
		} finally {
			ensureClose(zis);

			if (zos != null)
				zos.finish();
		}
	}

	private long computeCrc32(byte[] buf) {
		CRC32 crc = new CRC32();
		crc.update(buf, 0, buf.length);
		return crc.getValue();
	}

	private void traverse(File f) {
		if (!silent && canStatusReporting())
			printScanStatus();

		String path = f.getAbsolutePath();

		if (f.isDirectory()) {
			lastVisitDirectory = f;

			if (isExcluded(path)) {
				if (trace)
					System.out.println("Skipping excluded directory: " + path);

				return;
			}

			if (isSymlink(f)) {
				if (trace)
					System.out.println("Skipping symlink: " + path);

				return;
			}

			if (isExcludedDirectory(path)) {
				if (trace)
					System.out.println("Skipping directory: " + path);

				return;
			}

			if (trace)
				System.out.println("Scanning directory: " + path);

			scanDirCount++;

			File[] files = f.listFiles();
			if (files == null)
				return;

			for (File file : files) {
				traverse(file);
			}
		} else {
			scanFileCount++;

			if (noSymlink && isSymlink(f)) {
				if (trace)
					System.out.println("Skipping symlink: " + path);
			} else if (isScanTarget(path)) {
				if (trace)
					System.out.println("Scanning file: " + path);

				scanJarFile(f, fix);
			} else {
				if (trace)
					System.out.println("Skipping file: " + path);
			}
		}
	}

	private void printScanStatus() {
		long now = System.currentTimeMillis();
		int elapsed = (int) ((now - scanStartTime) / 1000);
		System.out.printf("Running scan (%ds): scanned %d directories, %d files, last visit: %s%n", elapsed, scanDirCount,
				scanFileCount, lastVisitDirectory.getAbsolutePath());

		lastStatusLoggingCount = scanFileCount;
		lastStatusLoggingTime = System.currentTimeMillis();
	}

	private boolean canStatusReporting() {
		// check scan file count to reduce system call overhead
		return scanFileCount - lastStatusLoggingCount >= 1000 && System.currentTimeMillis() - lastStatusLoggingTime >= 10000;
	}

	private boolean isSymlink(File f) {
		try {
			String canonicalPath = f.getCanonicalPath();
			String absolutePath = f.getAbsolutePath();

			if (isWindows) {
				canonicalPath = canonicalPath.toUpperCase();
				absolutePath = absolutePath.toUpperCase();
			}

			return !canonicalPath.contains(absolutePath);
		} catch (IOException e) {
		}

		return false;
	}

	private boolean isExcludedDirectory(String path) {
		if (isWindows && path.toUpperCase().indexOf("$RECYCLE.BIN") == 3)
			return true;

		return (path.equals("/proc") || path.startsWith("/proc/")) || (path.equals("/sys") || path.startsWith("/sys/"))
				|| (path.equals("/dev") || path.startsWith("/dev/")) || (path.equals("/run") || path.startsWith("/run/"))
				|| (path.equals("/var/run") || path.startsWith("/var/run/"));
	}

	private void scanJarFile(File jarFile, boolean fix) {
		ZipFile zipFile = null;
		InputStream is = null;
		boolean vulnerable = false;
		boolean mitigated = false;
		boolean potentiallyVulnerable = false;
		try {
			zipFile = new ZipFile(jarFile);

			Status status = checkLog4jVersion(jarFile, fix, zipFile);
			vulnerable = (status == Status.VULNERABLE);
			mitigated = (status == Status.MITIGATED);
			potentiallyVulnerable = (status == Status.POTENTIALLY_VULNERABLE);

			// scan nested jar files
			Enumeration<?> e = zipFile.entries();
			while (e.hasMoreElements()) {
				ZipEntry zipEntry = (ZipEntry) e.nextElement();
				if (!zipEntry.isDirectory() && isScanTarget(zipEntry.getName())) {
					Status nestedJarStatus = scanNestedJar(jarFile, zipFile, zipEntry);
					vulnerable |= (nestedJarStatus == Status.VULNERABLE);
					mitigated |= (nestedJarStatus == Status.MITIGATED);
					potentiallyVulnerable |= (nestedJarStatus == Status.POTENTIALLY_VULNERABLE);
				}
			}

			if (vulnerable)
				vulnerableFileCount++;
			else if (mitigated)
				mitigatedFileCount++;
			else if (potentiallyVulnerable)
				potentiallyVulnerableFileCount++;

			if (fix && vulnerable)
				vulnerableFiles.add(jarFile);

		} catch (ZipException e) {
			// ignore broken zip file
			System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
		} catch (IllegalArgumentException e) {
			if (e.getMessage().equals("MALFORMED")) {
				System.out.printf("Skipping broken jar file %s ('%s')%n", jarFile, e.getMessage());
			} else {
				System.out.printf("Scan error: '%s' on file: %s%n", e.getMessage(), jarFile);
				if (debug)
					e.printStackTrace();
			}
		} catch (Throwable t) {
			System.out.printf("Scan error: '%s' on file: %s%n", t.getMessage(), jarFile);
			if (debug)
				t.printStackTrace();
		} finally {
			ensureClose(is);
			ensureClose(zipFile);
		}
	}

	private Status checkLog4jVersion(File jarFile, boolean fix, ZipFile zipFile) throws IOException {
		ZipEntry entry = zipFile.getEntry(LOG4j_CORE_POM_PROPS);
		if (entry == null) {
			// Check for existence of JndiLookup.class; e.g. somebody repacked the entries
			// of the jars
			entry = zipFile.getEntry(JNDI_LOOKUP_CLASS_PATH);
			if (entry != null) {
				String path = jarFile.getAbsolutePath();
				printDetection(path, POTENTIALLY_VULNERABLE, false, true);
				return Status.POTENTIALLY_VULNERABLE;
			}
			return Status.NOT_VULNERABLE;
		}

		InputStream is = null;
		try {
			is = zipFile.getInputStream(entry);

			String version = loadVulnerableLog4jVersion(is);
			if (version != null) {
				boolean mitigated = zipFile.getEntry(JNDI_LOOKUP_CLASS_PATH) == null;
				String path = jarFile.getAbsolutePath();
				printDetection(path, version, mitigated, false);
				return mitigated ? Status.MITIGATED : Status.VULNERABLE;
			}

			return Status.NOT_VULNERABLE;
		} finally {
			ensureClose(is);
		}
	}

	private void printDetection(String path, String version, boolean mitigated, boolean potential) {
		String msg = potential ? "[?]" : "[*]";

		String cve = "CVE-2021-44228";
		if (version.startsWith("2.15."))
			cve = "CVE-2021-45046";

		msg += " Found " + cve + " vulnerability in " + path + ", log4j " + version;
		if (mitigated)
			msg += " (mitigated)";

		System.out.println(msg);
	}

	private Status scanNestedJar(File fatJarFile, ZipFile zipFile, ZipEntry zipEntry) {
		InputStream is = null;
		try {
			is = zipFile.getInputStream(zipEntry);
			List<String> pathChain = new ArrayList<String>();
			pathChain.add(zipEntry.getName());
			Status status = scanStream(fatJarFile, is, pathChain);
			return status;
		} catch (IOException e) {
			String msg = "cannot scan nested jar " + fatJarFile.getAbsolutePath() + ", entry " + zipEntry.getName();
			throw new IllegalStateException(msg, e);
		} finally {
			ensureClose(is);
		}
	}

	private Status scanStream(File fatJarFile, InputStream is, List<String> pathChain) {
		ZipInputStream zis = null;
		Status maxNestedJarStatus = Status.NOT_VULNERABLE;
		String vulnerableVersion = null;
		boolean mitigated = true;
		boolean pomFound = false;
		try {
			zis = new ZipInputStream(new DummyInputStream(is));

			while (true) {
				ZipEntry entry = zis.getNextEntry();
				if (entry == null)
					break;

				if (entry.getName().equals(LOG4j_CORE_POM_PROPS)) {
					vulnerableVersion = loadVulnerableLog4jVersion(zis);
					pomFound = true;
				}

				if (entry.getName().equals(JNDI_LOOKUP_CLASS_PATH)) {
					mitigated = false;
				}

				if (isScanTarget(entry.getName())) {
					pathChain.add(entry.getName());
					Status nestedStatus = scanStream(fatJarFile, zis, pathChain);
					if (nestedStatus.ordinal() > maxNestedJarStatus.ordinal())
						maxNestedJarStatus = nestedStatus;

					pathChain.remove(pathChain.size() - 1);
				}
			}

			if (vulnerableVersion != null) {
				String path = fatJarFile + " (" + toString(pathChain) + ")";
				printDetection(path, vulnerableVersion, mitigated, false);
				Status selfStatus = mitigated ? Status.MITIGATED : Status.VULNERABLE;
				return selfStatus.ordinal() > maxNestedJarStatus.ordinal() ? selfStatus : maxNestedJarStatus;
			}

			if (!mitigated && !pomFound) {
				String path = fatJarFile + " (" + toString(pathChain) + ")";
				printDetection(path, POTENTIALLY_VULNERABLE, false, true);

				if (maxNestedJarStatus.ordinal() > Status.POTENTIALLY_VULNERABLE.ordinal())
					return maxNestedJarStatus;
				return Status.POTENTIALLY_VULNERABLE;
			}

			if (maxNestedJarStatus != Status.NOT_VULNERABLE)
				return maxNestedJarStatus;

			return Status.NOT_VULNERABLE;
		} catch (IOException e) {
			// ignore WinRAR
			String entryName = pathChain.get(pathChain.size() - 1);
			if (entryName.toLowerCase().endsWith(".rar"))
				return Status.NOT_VULNERABLE;

			String msg = "cannot scan nested jar " + fatJarFile.getAbsolutePath() + ", path " + toString(pathChain);
			throw new IllegalStateException(msg, e);
		} finally {
//			ensureClose(zis);
		}
	}

	private String toString(List<String> pathChain) {
		StringBuilder sb = new StringBuilder();
		int i = 0;
		for (String path : pathChain) {
			if (i++ != 0)
				sb.append(" > ");
			sb.append(path);
		}

		return sb.toString();
	}

	private String loadVulnerableLog4jVersion(InputStream is) throws IOException {
		Properties props = new Properties();
		props.load(is);

		String groupId = props.getProperty("groupId");
		String artifactId = props.getProperty("artifactId");
		String version = props.getProperty("version");

		if (groupId.equals("org.apache.logging.log4j") && artifactId.equals("log4j-core")) {
			String[] tokens = version.split("\\.");
			int major = Integer.parseInt(tokens[0]);
			int minor = Integer.parseInt(tokens[1]);
			int patch = 0;

			// e.g. version 2.0 has only 2 tokens
			if (tokens.length > 2)
				patch = Integer.parseInt(tokens[2]);

			if (isVulnerable(major, minor, patch))
				return version;
		}

		return null;
	}

	private boolean isScanTarget(String path) {
		String loweredPath = path.toLowerCase();
		if (scanZip && loweredPath.endsWith(".zip"))
			return true;

		// ear = Java EE archive, aar = Android archive
		// rar = Java EE resource adapter archive (not WinRAR)
		return loweredPath.endsWith(".jar") || loweredPath.endsWith(".war") || loweredPath.endsWith(".ear")
				|| loweredPath.endsWith(".aar") || loweredPath.endsWith(".rar");
	}

	private boolean isExcluded(String path) {
		if (isWindows)
			path = path.toUpperCase();

		for (String excludePath : excludePaths) {
			if (path.startsWith(excludePath))
				return true;
		}
	
		for (String excludePattern : excludePatterns) {
			if (path.contains(excludePattern))
				return true;
		}

		return false;
	}

	private boolean isVulnerable(int major, int minor, int patch) {
		return major == 2 && minor < 16;
	}

	private void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}

	private void ensureClose(ZipFile zipFile) {
		if (zipFile != null) {
			try {
				zipFile.close();
			} catch (Throwable t) {
			}
		}
	}
}