package com.sftpdownloader;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class Config {
    // SFTP Settings
    public static class SftpConfig {
        public String host = "localhost";
        public int port = 22;
        public String username = "";
        public String password = "";
        public int connectionTimeout = 30000;
        public int authTimeout = 30000;
    }
    
    // Download Settings
    public static class DownloadConfig {
        public String remoteFile = "";
        public String remoteDirectory = ".";
        public String localDirectory = ".";
        public boolean downloadAll = false;
        public List<String> includePatterns = new ArrayList<>();
        public List<String> excludePatterns = new ArrayList<>();
        public boolean skipExisting = false;
        public boolean resumeDownload = false;
        // New: allow downloading directly from HTTP/HTTPS links (not SFTP)
        public boolean downloadFromLinks = false;
    }
    
    // Extraction Settings
    public static class ExtractionConfig {
        public boolean enabled = true;
        public boolean deleteAfterExtraction = false;
        public boolean createSubdirectory = false;
        public boolean preservePermissions = true;
        public List<String> supportedFormats = Arrays.asList(".tar.gz", ".tgz", ".tar", ".zip", ".gz");
    }
    
    // Logging Settings
    public static class LoggingConfig {
        public String level = "INFO";
        public boolean showProgress = true;
        public int progressInterval = 1000;
        public String logFile = "";
    }
    
    // Retry Settings
    public static class RetryConfig {
        public boolean enabled = true;
        public int maxAttempts = 3;
        public int retryDelay = 5000;
        public double backoffMultiplier = 2.0;
    }
    
    // Advanced Settings
    public static class AdvancedConfig {
        public int bufferSize = 8192;
        public boolean strictHostKeyChecking = false;
        public String knownHostsFile = "";
        public String preferredAuthentications = "password,publickey,keyboard-interactive";
        public int keepAliveInterval = 10000;
        public int compressionLevel = 0;
    }
    
    // Post-Processing Settings
    public static class PostProcessingConfig {
        public String executeCommand = "";
        public String moveToDirectory = "";
        public boolean createMarkerFile = false;
        public String notificationWebhook = "";
    }
    
    // Main configuration class members
    public SftpConfig sftp = new SftpConfig();
    public DownloadConfig download = new DownloadConfig();
    public ExtractionConfig extraction = new ExtractionConfig();
    public LoggingConfig logging = new LoggingConfig();
    public RetryConfig retry = new RetryConfig();
    public AdvancedConfig advanced = new AdvancedConfig();
    public PostProcessingConfig postProcessing = new PostProcessingConfig();
    
    // Configuration file paths to try
    private static final String[] CONFIG_PATHS = {
        "sftp-config.yml",
        "config.yml",
        "config/sftp-config.yml",
        "../sftp-config.yml"
    };
    
    /**
     * Load configuration from YAML file
     */
    public static Config load() throws IOException {
        // Try to find configuration file
        File configFile = findConfigFile();
        
        if (configFile == null) {
            System.out.println("No configuration file found. Using default values.");
            System.out.println("Create sftp-config.yml to customize settings.");
            return new Config();
        }
        
        System.out.println("Loading configuration from: " + configFile.getAbsolutePath());
        
        try (InputStream input = new FileInputStream(configFile)) {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(input);
            
            if (data == null) {
                return new Config();
            }
            
            Config config = new Config();
            
            // Parse SFTP settings
            if (data.containsKey("sftp")) {
                Map<String, Object> sftpData = (Map<String, Object>) data.get("sftp");
                if (sftpData != null) {
                    config.sftp.host = getString(sftpData, "host", config.sftp.host);
                    config.sftp.port = getInt(sftpData, "port", config.sftp.port);
                    config.sftp.username = getString(sftpData, "username", config.sftp.username);
                    config.sftp.password = getString(sftpData, "password", config.sftp.password);
                    config.sftp.connectionTimeout = getInt(sftpData, "connectionTimeout", config.sftp.connectionTimeout);
                    config.sftp.authTimeout = getInt(sftpData, "authTimeout", config.sftp.authTimeout);
                }
            }
            if (data.containsKey("download")) {
                Map<String, Object> dlData = (Map<String, Object>) data.get("download");
                if (dlData != null) {
                    config.download.remoteFile = getString(dlData, "remoteFile", config.download.remoteFile);
                    config.download.remoteDirectory = getString(dlData, "remoteDirectory", config.download.remoteDirectory);
                    config.download.localDirectory = getString(dlData, "localDirectory", config.download.localDirectory);
                    config.download.downloadAll = getBoolean(dlData, "downloadAll", config.download.downloadAll);
                    config.download.includePatterns = getStringList(dlData, "includePatterns", config.download.includePatterns);
                    config.download.excludePatterns = getStringList(dlData, "excludePatterns", config.download.excludePatterns);
                    config.download.skipExisting = getBoolean(dlData, "skipExisting", config.download.skipExisting);
                    config.download.resumeDownload = getBoolean(dlData, "resumeDownload", config.download.resumeDownload);
                    // Parse new option for downloading from HTTP/HTTPS links
                    config.download.downloadFromLinks = getBoolean(dlData, "downloadFromLinks", config.download.downloadFromLinks);
                }
            }
            
            // Parse Extraction settings
            if (data.containsKey("extraction")) {
                Map<String, Object> extData = (Map<String, Object>) data.get("extraction");
                if (extData != null) {
                    config.extraction.enabled = getBoolean(extData, "enabled", config.extraction.enabled);
                    config.extraction.deleteAfterExtraction = getBoolean(extData, "deleteAfterExtraction", config.extraction.deleteAfterExtraction);
                    config.extraction.createSubdirectory = getBoolean(extData, "createSubdirectory", config.extraction.createSubdirectory);
                    config.extraction.preservePermissions = getBoolean(extData, "preservePermissions", config.extraction.preservePermissions);
                    config.extraction.supportedFormats = getStringList(extData, "supportedFormats", config.extraction.supportedFormats);
                }
            }
            
            // Parse Logging settings
            if (data.containsKey("logging")) {
                Map<String, Object> logData = (Map<String, Object>) data.get("logging");
                if (logData != null) {
                    config.logging.level = getString(logData, "level", config.logging.level);
                    config.logging.showProgress = getBoolean(logData, "showProgress", config.logging.showProgress);
                    config.logging.progressInterval = getInt(logData, "progressInterval", config.logging.progressInterval);
                    config.logging.logFile = getString(logData, "logFile", config.logging.logFile);
                }
            }
            
            // Parse Retry settings
            if (data.containsKey("retry")) {
                Map<String, Object> retryData = (Map<String, Object>) data.get("retry");
                if (retryData != null) {
                    config.retry.enabled = getBoolean(retryData, "enabled", config.retry.enabled);
                    config.retry.maxAttempts = getInt(retryData, "maxAttempts", config.retry.maxAttempts);
                    config.retry.retryDelay = getInt(retryData, "retryDelay", config.retry.retryDelay);
                    config.retry.backoffMultiplier = getDouble(retryData, "backoffMultiplier", config.retry.backoffMultiplier);
                }
            }
            
            // Parse Advanced settings
            if (data.containsKey("advanced")) {
                Map<String, Object> advData = (Map<String, Object>) data.get("advanced");
                if (advData != null) {
                    config.advanced.bufferSize = getInt(advData, "bufferSize", config.advanced.bufferSize);
                    config.advanced.strictHostKeyChecking = getBoolean(advData, "strictHostKeyChecking", config.advanced.strictHostKeyChecking);
                    config.advanced.knownHostsFile = getString(advData, "knownHostsFile", config.advanced.knownHostsFile);
                    config.advanced.preferredAuthentications = getString(advData, "preferredAuthentications", config.advanced.preferredAuthentications);
                    config.advanced.keepAliveInterval = getInt(advData, "keepAliveInterval", config.advanced.keepAliveInterval);
                    config.advanced.compressionLevel = getInt(advData, "compressionLevel", config.advanced.compressionLevel);
                }
            }
            
            // Parse Post-Processing settings
            if (data.containsKey("postProcessing")) {
                Map<String, Object> ppData = (Map<String, Object>) data.get("postProcessing");
                if (ppData != null) {
                    config.postProcessing.executeCommand = getString(ppData, "executeCommand", config.postProcessing.executeCommand);
                    config.postProcessing.moveToDirectory = getString(ppData, "moveToDirectory", config.postProcessing.moveToDirectory);
                    config.postProcessing.createMarkerFile = getBoolean(ppData, "createMarkerFile", config.postProcessing.createMarkerFile);
                    config.postProcessing.notificationWebhook = getString(ppData, "notificationWebhook", config.postProcessing.notificationWebhook);
                }
            }
            
            return config;
        }
    }
    
    /**
     * Find configuration file
     */
    private static File findConfigFile() {
        for (String path : CONFIG_PATHS) {
            File file = new File(path);
            if (file.exists() && file.isFile()) {
                return file;
            }
        }
        return null;
    }
    
    // Helper methods for safe type conversion
    private static String getString(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        return value != null ? value.toString() : defaultValue;
    }
    
    private static int getInt(Map<String, Object> map, String key, int defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return defaultValue;
    }
    
    private static double getDouble(Map<String, Object> map, String key, double defaultValue) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return defaultValue;
    }
    
    private static boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return defaultValue;
    }
    
    private static List<String> getStringList(Map<String, Object> map, String key, List<String> defaultValue) {
        Object value = map.get(key);
        if (value instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (item != null) {
                    result.add(item.toString());
                }
            }
            return result;
        }
        return defaultValue;
    }
}
