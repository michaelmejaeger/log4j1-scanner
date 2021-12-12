package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class Log4j2Scanner {

	private long scanDirCount = 0;
	private long scanFileCount = 0;
	private long vulnerableFileCount = 0;
	private long fixedFileCount = 0;

	private List<File> vulnerableFiles = new LinkedList<File>();

	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("Logpresso CVE-2021-44228 Vulnerability Scanner (2021-12-12)");
			System.out.println("Usage: log4j2-scan [--fix] target_path");
			return;
		}

		boolean fix = false;
		String path = null;
		if (args.length >= 2) {
			if (!args[0].equals("--fix")) {
				System.out.println("unsupported option: " + args[0]);
				return;
			}

			fix = true;
			path = args[1];
		} else {
			path = args[0];
		}

		if (fix) {
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
			}
		}

		File f = new File(path);
		new Log4j2Scanner().run(f, fix);
	}

	public void run(File f, boolean fix) {
		long begin = System.currentTimeMillis();
		try {
			traverse(f, fix);
			if (fix)
				fix();
		} finally {
			long elapsed = System.currentTimeMillis() - begin;
			System.out.println();
			System.out.println("Scanned " + scanDirCount + " directories and " + scanFileCount + " files");
			System.out.println("Found " + vulnerableFileCount + " vulnerable files");
			if (fix)
				System.out.println("Fixed " + vulnerableFiles.size() + " vulnerable files");

			System.out.printf("Completed in %.2f seconds\n", elapsed / 1000.0);
		}
	}

	private void fix() {
		for (File f : vulnerableFiles) {
			File backupFile = new File(f.getAbsolutePath() + ".bak");
			if (f.renameTo(backupFile))
				copyExceptJndiLookup(backupFile, f);
		}
	}

	private void copyExceptJndiLookup(File srcFile, File dstFile) {
		ZipFile srcZipFile = null;
		ZipOutputStream zos = null;

		try {
			srcZipFile = new ZipFile(srcFile);
			zos = new ZipOutputStream(new FileOutputStream(dstFile));

			Enumeration<?> e = srcZipFile.entries();
			while (e.hasMoreElements()) {
				ZipEntry entry = (ZipEntry) e.nextElement();

				if (entry.getName().equals("org/apache/logging/log4j/core/lookup/JndiLookup.class"))
					continue;

				if (entry.isDirectory()) {
					zos.putNextEntry(new ZipEntry(entry.getName()));
					continue;
				}

				zos.putNextEntry(new ZipEntry(entry.getName()));

				copyZipEntry(srcZipFile, entry, zos);
			}
		} catch (Throwable t) {
			System.out.println("Cannot fix file. rollback original file " + dstFile.getAbsolutePath());
			dstFile.delete();
			srcFile.renameTo(dstFile);
		} finally {
			ensureClose(srcZipFile);
			ensureClose(zos);
		}
	}

	private void copyZipEntry(ZipFile srcZipFile, ZipEntry entry, ZipOutputStream zos) throws IOException {
		InputStream is = null;
		try {
			is = srcZipFile.getInputStream(entry);

			byte[] buf = new byte[32768];
			while (true) {
				int len = is.read(buf);
				if (len < 0)
					break;

				zos.write(buf, 0, len);
			}
		} finally {
			ensureClose(is);
		}
	}

	private void traverse(File f, boolean fix) {
		if (f.isDirectory()) {
			scanDirCount++;

			File[] files = f.listFiles();
			if (files == null)
				return;

			for (File file : files) {
				traverse(file, fix);
			}
		} else {
			scanFileCount++;

			String path = f.getAbsolutePath();
			if (path.toLowerCase().endsWith(".jar")) {
				checkMavenProperties(f, fix);
			}
		}
	}

	private void checkMavenProperties(File f, boolean fix) {
		ZipFile zipFile = null;
		InputStream is = null;
		try {
			zipFile = new ZipFile(f);

			ZipEntry entry = zipFile.getEntry("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties");
			if (entry == null)
				return;

			is = zipFile.getInputStream(entry);
			Properties props = new Properties();
			props.load(is);

			String groupId = props.getProperty("groupId");
			String artifactId = props.getProperty("artifactId");
			String version = props.getProperty("version");

			if (groupId.equals("org.apache.logging.log4j") && artifactId.equals("log4j-core")) {
				String[] tokens = version.split("\\.");
				int major = Integer.parseInt(tokens[0]);
				int minor = Integer.parseInt(tokens[1]);
				int patch = Integer.parseInt(tokens[2]);

				if (isVulnerable(major, minor, patch)) {
					boolean mitigated = zipFile.getEntry("org/apache/logging/log4j/core/lookup/JndiLookup.class") == null;
					String msg = "[*] Found CVE-2021-44228 vulnerability in " + f.getAbsolutePath() + ", log4j " + version;
					if (mitigated)
						msg += " (mitigated)";

					System.out.println(msg);
					vulnerableFileCount++;

					if (fix && !mitigated)
						vulnerableFiles.add(f);
				}
			}

		} catch (Throwable t) {
			System.out.println("error: " + t.getMessage());
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (Throwable t) {
				}
			}

			ensureClose(zipFile);
		}
	}

	private boolean isVulnerable(int major, int minor, int patch) {
		return major == 2 && (minor < 14 || (minor == 14 && patch <= 1));
	}

	private void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}

}