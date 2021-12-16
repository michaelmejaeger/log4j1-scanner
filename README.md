![Logpresso Logo](logo.png)

log4j1-scan is a single binary command-line tool for scanning and mitigating the following vulnerabilities known in log4j version 1:

* CVE-2019-17571
* CVE-2021-4104

Mitigation is performed by excluding potentially dangerous classes from the respective archives (.jar, .ear, .war, .aar, .rar and optional .zip).
It also supports nested archive file scanning and patch.
This work is based on [Logpresso CVE-2021-44228](https://github.com/logpresso/CVE-2021-44228-Scanner), which does the same for log4j version 2.

### How to use
Just run log4j1-scan.exe or log4j2-scan with target directory path.

Usage
```
Usage: log4j1-scan [--fix] target_path

--fix
  Backup original file and remove dangerous classes from archive recursively.
--force-fix
  Do not prompt confirmation. Don't use this option unless you know what you are doing.
--keep-backup
  Keep the backup of the original file for each file that is modified. The extension of the keepBackup file is '.bak'.
--debug
  Print exception stacktrace for debugging.
--trace
  Print all directories and files while scanning.
--silent
  Do not print anything until scan is completed.
--scan-zip
  Scan also .zip extension files. This option may slow down scanning.
--no-symlink
  Do not detect symlink as vulnerable file.
--exclude [path_prefix]
  Exclude specified paths. You can specify multiple --exclude [path_prefix] pairs
--exclude-config [file_path]
--exclude-pattern [pattern]
  Exclude specified paths by pattern. You can specify multiple --exclude-pattern [pattern] pairs (non regex)
  Specify exclude path list in text file. Paths should be separated by new line. Prepend # for comment.
--all-drives
  Scan all drives on Windows
--drives c,d
  Scan specified drives on Windows. Spaces are not allowed here.
```

On Linux
```
java -jar log4j1-scanner-1.1.0 [--fix] target_path
```

If you add `--fix` option, this program will copy vulnerable original JAR file to .bak file, and create new JAR file without the potentially dangerous class files. However, you must use this option at your own risk. It is necessary to shutdown any running JVM process before applying patch. This backup file is only kept if the switch `--backup` is used. Start affected JVM process after fix.

If you want to automate patch job, use `--force-fix` option. With this option, this program will no longer prompt for confirmation.

`(mitigated)` tag will be displayed if the potentially dangerous class files are removed from the respective archive.

If you add `--trace` option, this program will print all visited directories and files. Use this option only for debugging.

### How it works
Run in 5 steps:
1. Find all .jar, .war, .ear, .aar files recursively.
2. Find `META-INF/maven/log4j/log4j/pom.properties` entry from JAR file. If this is missing, the archive is considered as potentially vulnerable in case in contains the dangerous class files.
3. Read groupId, artifactId, and version.
4. Compare log4j1 version and print vulnerable version.
5. If --fix option is used, backup vulnerable file and patch it.
   * For example, original vulnerable.jar is copied to vulnerable.jar.bak

### Contact
If you have any question or issue, create an issue in this repository.
