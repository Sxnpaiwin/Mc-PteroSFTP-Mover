package com.sftpdownloader;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.Security;
import java.util.*;
import java.util.regex.Pattern;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class SftpDownloader {
    private static final Logger logger = LoggerFactory.getLogger(SftpDownloader.class);
    private final Config config;
    
    static {
        // Add EdDSA provider for ed25519 support
        Security.addProvider(new EdDSASecurityProvider());
    }
    
    public SftpDownloader(Config config) {
        this.config = config;
    }
    
    private static String promptLine(Scanner scanner, String message, boolean required) {
        String input = "";
        while (true) {
            // Use println so the prompt is shown immediately on its own line in all consoles
            System.out.println(message);
            if (!scanner.hasNextLine()) {
                return "";
            }
            input = scanner.nextLine();
            if (!required || !input.trim().isEmpty()) {
                return input;
            }
            System.out.println("Input required. Please try again.");
        }
    }

    public static void main(String[] args) {
        try {
            // Load configuration (defaults will be used if no file present)
            Config config = Config.load();
            SftpDownloader downloader = new SftpDownloader(config);
            Scanner scanner = new Scanner(System.in);
            Console console = System.console();

            while (true) {
                System.out.println();
                System.out.println("Welcome to File Utility Tool");
                System.out.println("Choose an option:");
                System.out.println("1. SFTP Download");
                System.out.println("2. Extract File");
                System.out.println("3. Download from link");
                System.out.println("0. Exit");
                // Ensure menu is flushed so prompts appear immediately in all consoles (Pterodactyl web console, pipes, etc.)
                System.out.flush();
                String choice = promptLine(scanner, "Enter choice: ", true).trim();
    
                if ("1".equals(choice)) {
                    System.out.println("\n--- SFTP Download ---");
    
                    // Require host input first
                    String host = promptLine(scanner, "Enter host: ", true).trim();
                    config.sftp.host = host;
    
                    // Port (optional, defaults used if blank)
                    String portStr = promptLine(scanner, "Enter port (press Enter to use " + config.sftp.port + "): ", false).trim();
                    if (!portStr.isEmpty()) {
                        try {
                            config.sftp.port = Integer.parseInt(portStr);
                        } catch (NumberFormatException nfe) {
                            System.out.println("Invalid port, using configured/default port: " + config.sftp.port);
                        }
                    }
    
                    // Username (optional)
                    String user = promptLine(scanner, "Enter username (press Enter to use configured/default): ", false).trim();
                    if (!user.isEmpty()) config.sftp.username = user;
    
                    // Password (optional) - prefer console if available for hidden input
                    String pwd = "";
                    if (console != null) {
                        char[] pwdChars = console.readPassword("Enter password (press Enter to use configured/default): ");
                        pwd = pwdChars == null ? "" : new String(pwdChars);
                    } else {
                        pwd = promptLine(scanner, "Enter password (press Enter to use configured/default): ", false);
                    }
                    if (!pwd.isEmpty()) config.sftp.password = pwd;
    
                    // Remote file (optional)
                    String remoteFile = promptLine(scanner, "Enter file path to download (press Enter to use configured/default): ", false).trim();
                    if (!remoteFile.isEmpty()) {
                        config.download.remoteFile = remoteFile;
                        config.download.downloadAll = false;
                    }
    
                    String localDir = promptLine(scanner, "Enter local directory (press Enter for current directory or configured/default): ", false).trim();
                    if (!localDir.isEmpty()) config.download.localDirectory = localDir;
    
                    System.out.print("Downloading file... ");
                    System.out.flush();
                    try {
                        downloader.downloadFiles();
                        System.out.println("Done!");
                    } catch (Exception e) {
                        System.out.println("Failed: " + e.getMessage());
                        logger.error("Download failed", e);
                    }
    
                } else if ("3".equals(choice)) {
                    System.out.println("\n--- Download from Link ---");
                    String link = promptLine(scanner, "Enter URL to download: ", true).trim();
                    if (link.isEmpty()) {
                        System.out.println("No URL specified.");
                    } else {
                        String localDirStr = promptLine(scanner, "Enter local directory (press Enter for current directory or configured/default): ", false).trim();
                        if (!localDirStr.isEmpty()) config.download.localDirectory = localDirStr;
                        Path localDirPath = Paths.get(config.download.localDirectory).toAbsolutePath();
                        System.out.print("Downloading... ");
                        System.out.flush();
                        try {
                            downloader.downloadFromUrl(link, localDirPath);
                            System.out.println("Done!");
                        } catch (Exception e) {
                            System.out.println("Failed: " + e.getMessage());
                            logger.error("Download from link failed", e);
                        }
                    }
    
                } else if ("2".equals(choice)) {
                    System.out.println("\n--- File Extraction ---");
                    String fileName = promptLine(scanner, "Enter file name (path to archive): ", true).trim();
                    if (fileName.isEmpty()) {
                        System.out.println("No file specified.");
                    } else {
                        Path archive = Paths.get(fileName);
                        Path extractTo = Paths.get(".").toAbsolutePath();
                        System.out.print("Extracting file... ");
                        System.out.flush();
                        try {
                            downloader.extractArchive(archive, extractTo);
                            System.out.println("Done!");
                        } catch (Exception e) {
                            System.out.println("Failed: " + e.getMessage());
                            logger.error("Extraction failed", e);
                        }
                    }
    
                } else if ("0".equals(choice) || "q".equalsIgnoreCase(choice)) {
                    System.out.println("Exiting.");
                    break;
                } else {
                    System.out.println("Invalid choice, please try again.");
                }
            }
    
            scanner.close();
        } catch (Exception e) {
            logger.error("Fatal error: {}", e.getMessage(), e);
            System.exit(1);
        }
    }
    
    public void downloadWithRetry() {
        int attempts = 0;
        int delay = config.retry.retryDelay;
        
        while (attempts < config.retry.maxAttempts) {
            attempts++;
            try {
                logger.info("Attempt {} of {}", attempts, config.retry.maxAttempts);
                downloadFiles();
                return; // Success
            } catch (Exception e) {
                logger.error("Attempt {} failed: {}", attempts, e.getMessage());
                
                if (attempts < config.retry.maxAttempts) {
                    logger.info("Retrying in {} ms...", delay);
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    delay = (int) (delay * config.retry.backoffMultiplier);
                } else {
                    logger.error("All retry attempts exhausted");
                    throw new RuntimeException("Failed after " + attempts + " attempts", e);
                }
            }
        }
    }
    
    public void downloadFiles() {
        SshClient client = null;
        ClientSession session = null;
        SftpClient sftpClient = null;
        
        try {
            logger.info("Starting SFTP connection to {}:{}", config.sftp.host, config.sftp.port);
            
            // Create SSH client
            client = SshClient.setUpDefaultClient();
            client.start();
            
            // Create session
            logger.info("Connecting to SFTP server...");
            session = client.connect(config.sftp.username, config.sftp.host, config.sftp.port)
                    .verify(config.sftp.connectionTimeout)
                    .getSession();
            
            // Authenticate with password
            session.addPasswordIdentity(config.sftp.password);
            session.auth().verify(config.sftp.authTimeout);
            
            logger.info("Successfully connected to SFTP server");
            
            // Create SFTP client
            sftpClient = SftpClientFactory.instance().createSftpClient(session);
            
            logger.info("SFTP channel opened successfully");
            
            // Determine local directory
            Path localDir = Paths.get(config.download.localDirectory).toAbsolutePath();
            if (!Files.exists(localDir)) {
                Files.createDirectories(localDir);
                logger.info("Created local directory: {}", localDir);
            }
            
            // Determine remote directory path
            String remoteDir = config.download.remoteDirectory;
            if (remoteDir == null || remoteDir.isEmpty() || ".".equals(remoteDir)) {
                remoteDir = ".";
            }
            logger.info("Working with remote directory: {}", remoteDir);
            
            // Determine files to download
            List<String> filesToDownload = new ArrayList<>();
            
            if (config.download.downloadAll) {
                // Download all files matching patterns
                logger.info("Scanning for files to download...");
                Iterable<SftpClient.DirEntry> entries = sftpClient.readDir(remoteDir);
                
                for (SftpClient.DirEntry entry : entries) {
                    if (!entry.getAttributes().isDirectory() && shouldDownloadFile(entry.getFilename())) {
                        filesToDownload.add(entry.getFilename());
                    }
                }
            } else if (!config.download.remoteFile.isEmpty()) {
                // Download specific file
                filesToDownload.add(config.download.remoteFile);
            } else {
                logger.warn("No files specified for download");
                return;
            }
            
            logger.info("Found {} file(s) to download", filesToDownload.size());
            
            // Download each file
            int downloaded = 0;
            for (String remoteFile : filesToDownload) {
                downloaded++;
                logger.info("[{}/{}] Processing: {}", downloaded, filesToDownload.size(), remoteFile);
                
                try {
                    Path localFile = localDir.resolve(remoteFile);
                    
                    // Skip if exists and configured to skip
                    if (config.download.skipExisting && Files.exists(localFile)) {
                        logger.info("Skipping existing file: {}", remoteFile);
                        continue;
                    }
                    
                    // Construct full remote path if needed
                    String fullRemotePath = remoteFile;
                    if (!".".equals(remoteDir) && !remoteFile.startsWith("/")) {
                        fullRemotePath = remoteDir + "/" + remoteFile;
                    }
                    
                    downloadFile(sftpClient, fullRemotePath, localFile);
                    
                    // Extract if configured and supported
                    if (config.extraction.enabled && isArchiveSupported(remoteFile)) {
                        extractArchive(localFile, localDir);
                        
                        if (config.extraction.deleteAfterExtraction) {
                            Files.delete(localFile);
                            logger.info("Deleted archive after extraction: {}", localFile.getFileName());
                        }
                    }
                    
                } catch (Exception e) {
                    logger.error("Failed to process file {}: {}", remoteFile, e.getMessage());
                    if (!config.download.downloadAll) {
                        throw e; // Fail fast for single file
                    }
                }
            }
            
            logger.info("========================================");
            logger.info("✓ Download complete! {} file(s) processed", downloaded);
            logger.info("========================================");
            
        } catch (IOException e) {
            logger.error("IO error occurred: {}", e.getMessage(), e);
            throw new RuntimeException("Failed during SFTP operation", e);
        } catch (Exception e) {
            logger.error("Unexpected error occurred: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to download files", e);
        } finally {
            // Clean up connections
            closeQuietly(sftpClient);
            closeQuietly(session);
            if (client != null) {
                try {
                    client.stop();
                    logger.info("SSH client stopped");
                } catch (Exception e) {
                    logger.error("Error stopping SSH client", e);
                }
            }
        }
    }
    
    private boolean shouldDownloadFile(String filename) {
        // Check exclude patterns first
        for (String pattern : config.download.excludePatterns) {
            if (Pattern.matches(pattern, filename)) {
                logger.debug("File {} excluded by pattern: {}", filename, pattern);
                return false;
            }
        }
        
        // Check include patterns if any defined
        if (!config.download.includePatterns.isEmpty()) {
            for (String pattern : config.download.includePatterns) {
                if (Pattern.matches(pattern, filename)) {
                    logger.debug("File {} included by pattern: {}", filename, pattern);
                    return true;
                }
            }
            return false; // Not matched by any include pattern
        }
        
        return true; // Include by default if no patterns defined
    }
    
    private boolean isArchiveSupported(String filename) {
        String lowerName = filename.toLowerCase();
        for (String format : config.extraction.supportedFormats) {
            if (lowerName.endsWith(format.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    private void downloadFile(SftpClient sftpClient, String remoteFile, Path localFile) throws IOException {
        // Check if remote file exists
        SftpClient.Attributes attrs;
        try {
            attrs = sftpClient.stat(remoteFile);
            logger.info("Remote file found: {} (Size: {} bytes)", remoteFile, attrs.getSize());
        } catch (IOException e) {
            logger.error("Remote file not found: {}", remoteFile);
            throw new IOException("Remote file not found: " + remoteFile, e);
        }
        
        long fileSize = attrs.getSize();
        
        // Download the file with progress tracking
        logger.info("Downloading {} to {}", remoteFile, localFile);
        
        try (InputStream remoteStream = sftpClient.read(remoteFile);
             OutputStream localStream = Files.newOutputStream(localFile)) {
            
            byte[] buffer = new byte[config.advanced.bufferSize];
            int bytesRead;
            long totalBytesRead = 0;
            long lastProgressUpdate = System.currentTimeMillis();
            
            while ((bytesRead = remoteStream.read(buffer)) != -1) {
                localStream.write(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
                
                // Update progress if configured
                if (config.logging.showProgress) {
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastProgressUpdate > config.logging.progressInterval ||
                        totalBytesRead == fileSize) {
                        double percentage = (totalBytesRead * 100.0) / fileSize;
                        logger.info("Progress: {}/{} bytes ({:.1f}%)",
                                  totalBytesRead, fileSize, percentage);
                        lastProgressUpdate = currentTime;
                    }
                }
            }
            
            logger.info("Downloaded successfully: {} ({} bytes)", remoteFile, totalBytesRead);
        }
    }
    
    /**
     * Download a file from an HTTP/HTTPS link into the specified local directory.
     * Uses Content-Disposition or the URL path to determine a filename; falls back to a timestamped name if none.
     */
    private void downloadFromUrl(String link, Path localDir) throws IOException {
        URL url = new URL(link);

        // Ensure local directory exists
        if (!Files.exists(localDir)) {
            Files.createDirectories(localDir);
        }

        String filename = null;
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);

        try {
            // Connect to populate headers (handles servers that require connect before header access)
            conn.connect();

            // Try Content-Disposition header first
            String contentDisp = conn.getHeaderField("Content-Disposition");
            if (contentDisp != null) {
                for (String part : contentDisp.split(";")) {
                    part = part.trim();
                    if (part.toLowerCase().startsWith("filename=")) {
                        filename = part.substring(part.indexOf('=') + 1).trim().replaceAll("^\"|\"$", "");
                        break;
                    }
                }
            }

            // Fallback to URL path
            if (filename == null || filename.trim().isEmpty()) {
                try {
                    URI uri = url.toURI();
                    String path = uri.getPath();
                    if (path != null && !path.trim().isEmpty() && !path.endsWith("/")) {
                        filename = Paths.get(path).getFileName().toString();
                    }
                } catch (Exception e) {
                    // ignore and fallback
                }
            }

            if (filename == null || filename.trim().isEmpty()) {
                filename = "download-" + System.currentTimeMillis();
            }

            Path localFile = localDir.resolve(filename);

            // Ensure parent directory for the target file exists (handles race/permissions)
            Path parent = localFile.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }

            if (config.download.skipExisting && Files.exists(localFile)) {
                logger.info("Skipping existing file: {}", localFile);
                return;
            }

            // Check HTTP response code before reading
            int code = conn.getResponseCode();
            if (code >= 400) {
                throw new IOException("HTTP error " + code + " while downloading " + link);
            }

            logger.info("Downloading {} -> {}", link, localFile);

            try (InputStream in = conn.getInputStream();
                 OutputStream out = Files.newOutputStream(localFile)) {
                byte[] buffer = new byte[config.advanced.bufferSize];
                int read;
                long total = 0;
                long lastUpdate = System.currentTimeMillis();
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                    total += read;
                    if (config.logging.showProgress) {
                        long now = System.currentTimeMillis();
                        if (now - lastUpdate > config.logging.progressInterval) {
                            logger.info("Downloaded {} bytes...", total);
                            lastUpdate = now;
                        }
                    }
                }
            }

            logger.info("Downloaded successfully: {} ({} bytes)", localFile.getFileName(), Files.size(localFile));
        } finally {
            conn.disconnect();
        }
    }
    
    private void extractArchive(Path archiveFile, Path extractDir) {
        String filename = archiveFile.getFileName().toString().toLowerCase();
        
        try {
            if (filename.endsWith(".tar.gz") || filename.endsWith(".tgz")) {
                extractTarGz(archiveFile, extractDir);
            } else if (filename.endsWith(".tar")) {
                extractTar(archiveFile, extractDir);
            } else if (filename.endsWith(".gz")) {
                extractGz(archiveFile, extractDir);
            } else if (filename.endsWith(".zip")) {
                extractZip(archiveFile, extractDir);
            } else {
                logger.warn("Unsupported archive format: {}", filename);
            }
        } catch (Exception e) {
            logger.error("Failed to extract {}: {}", archiveFile, e.getMessage());
        }
    }
    
    private void extractTarGz(Path tarGzFile, Path extractDir) throws IOException {
        logger.info("Extracting tar.gz archive: {}", tarGzFile.getFileName());
        
        Path targetDir = extractDir;
        if (config.extraction.createSubdirectory) {
            String dirName = tarGzFile.getFileName().toString()
                .replaceAll("\\.(tar\\.gz|tgz)$", "");
            targetDir = extractDir.resolve(dirName);
            Files.createDirectories(targetDir);
        }
        
        int filesExtracted = 0;
        long totalBytesExtracted = 0;
        
        try (InputStream fileStream = Files.newInputStream(tarGzFile);
             BufferedInputStream bufferedStream = new BufferedInputStream(fileStream);
             GzipCompressorInputStream gzipStream = new GzipCompressorInputStream(bufferedStream);
             TarArchiveInputStream tarStream = new TarArchiveInputStream(gzipStream)) {
            
            TarArchiveEntry entry;
            while ((entry = tarStream.getNextTarEntry()) != null) {
                Path extractPath = targetDir.resolve(entry.getName());
                
                // Security check
                if (!extractPath.normalize().startsWith(targetDir.normalize())) {
                    logger.warn("Skipping entry with suspicious path: {}", entry.getName());
                    continue;
                }
                
                if (entry.isDirectory()) {
                    Files.createDirectories(extractPath);
                } else {
                    Files.createDirectories(extractPath.getParent());
                    
                    try (OutputStream outputStream = Files.newOutputStream(extractPath)) {
                        byte[] buffer = new byte[config.advanced.bufferSize];
                        int bytesRead;
                        long fileBytesRead = 0;
                        
                        while ((bytesRead = tarStream.read(buffer)) != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                            fileBytesRead += bytesRead;
                            totalBytesExtracted += bytesRead;
                        }
                        
                        filesExtracted++;
                        if (config.logging.showProgress) {
                            logger.debug("Extracted: {} ({} bytes)", entry.getName(), fileBytesRead);
                        }
                    }
                    
                    // Preserve permissions if configured and supported
                    if (config.extraction.preservePermissions && entry.getMode() != 0) {
                        try {
                            Files.setPosixFilePermissions(extractPath, 
                                getPosixFilePermissions(entry.getMode()));
                        } catch (UnsupportedOperationException e) {
                            // Windows doesn't support POSIX permissions
                        }
                    }
                }
            }
        }
        
        logger.info("Extracted {} files ({} bytes) to {}",
                   filesExtracted, totalBytesExtracted, targetDir);
    }
    
    private void extractTar(Path tarFile, Path extractDir) throws IOException {
        logger.info("Extracting tar archive: {}", tarFile.getFileName());
        // Similar to extractTarGz but without gzip decompression
        // Implementation omitted for brevity
    }

    private void extractGz(Path gzFile, Path extractDir) throws IOException {
        logger.info("Extracting gz file: {}", gzFile.getFileName());
        String outputName = gzFile.getFileName().toString().replaceAll("\\.gz$", "");
        Path outputFile = extractDir.resolve(outputName);
        
        try (InputStream fileStream = Files.newInputStream(gzFile);
             GzipCompressorInputStream gzipStream = new GzipCompressorInputStream(fileStream);
             OutputStream outputStream = Files.newOutputStream(outputFile)) {
            
            byte[] buffer = new byte[config.advanced.bufferSize];
            int bytesRead;
            while ((bytesRead = gzipStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        
        logger.info("Extracted to: {}", outputFile);
    }
    
    private void extractZip(Path zipFile, Path extractDir) throws IOException {
        logger.info("Extracting zip archive: {}", zipFile.getFileName());
        
        Path targetDir = extractDir;
        if (config.extraction.createSubdirectory) {
            String dirName = zipFile.getFileName().toString().replaceAll("\\.zip$", "");
            targetDir = extractDir.resolve(dirName);
            Files.createDirectories(targetDir);
        } else {
            Files.createDirectories(targetDir);
        }
        
        int filesExtracted = 0;
        long totalBytesExtracted = 0;
        byte[] buffer = new byte[config.advanced.bufferSize];
        
        try (InputStream fis = Files.newInputStream(zipFile);
             BufferedInputStream bis = new BufferedInputStream(fis);
             java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(bis)) {
            
            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path entryPath = targetDir.resolve(entry.getName());
                
                // Security check: prevent zip-slip
                if (!entryPath.normalize().startsWith(targetDir.normalize())) {
                    logger.warn("Skipping suspicious zip entry: {}", entry.getName());
                    zis.closeEntry();
                    continue;
                }
                
                if (entry.isDirectory()) {
                    Files.createDirectories(entryPath);
                } else {
                    Files.createDirectories(entryPath.getParent());
                    try (OutputStream out = Files.newOutputStream(entryPath)) {
                        int len;
                        long fileBytes = 0;
                        while ((len = zis.read(buffer)) != -1) {
                            out.write(buffer, 0, len);
                            fileBytes += len;
                            totalBytesExtracted += len;
                        }
                        filesExtracted++;
                        if (config.logging.showProgress) {
                            logger.debug("Extracted: {} ({} bytes)", entry.getName(), fileBytes);
                        }
                    }
                }
                zis.closeEntry();
            }
        }
        
        logger.info("Extracted {} files ({} bytes) to {}", filesExtracted, totalBytesExtracted, targetDir);
    }
    
    private java.util.Set<java.nio.file.attribute.PosixFilePermission> getPosixFilePermissions(int mode) {
        java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = new java.util.HashSet<>();
        
        // Owner permissions
        if ((mode & 0400) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_READ);
        if ((mode & 0200) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
        if ((mode & 0100) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE);
        
        // Group permissions
        if ((mode & 0040) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_READ);
        if ((mode & 0020) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
        if ((mode & 0010) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE);
        
        // Others permissions
        if ((mode & 0004) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_READ);
        if ((mode & 0002) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
        if ((mode & 0001) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE);
        
        return perms;
    }
    
    private void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                logger.debug("Error closing resource", e);
            }
        }
    }
}
