// Intentionally vulnerable test fixture for CyberGuard SAST testing.
// DO NOT USE IN PRODUCTION.

const { exec } = require("child_process");
const fs = require("fs");

function backupDirectory(targetDir) {
    // Rule CG-CMDI-001: Command injection via unescaped string concatenation
    exec("tar -czf backup.tar.gz " + targetDir, (error, stdout, stderr) => {
        if (error) {
            console.error(`Backup error: ${error}`);
            return;
        }
        console.log(`Backup completed: ${stdout}`);
    });
}

function readConfig(userPath) {
    // Rule CG-PATH-001: Path traversal sequence
    const safeBase = "/app/config/";
    const filePath = safeBase + "../" + userPath;
    return fs.readFileSync(filePath, "utf8");
}

module.exports = { backupDirectory, readConfig };
