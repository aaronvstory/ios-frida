// Enhanced version that actually saves the log file to the ban-notes directory
// This companion script handles the file writing since Frida can't directly write to Windows filesystem

const fs = require('fs');
const path = require('path');

// Create ban-notes directory if it doesn't exist
const logDir = path.join(__dirname, 'ban-notes');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Function to save dasher info to file
function saveDasherLog(dasherInfo, formattedOutput) {
    const timestamp = new Date().toISOString()
        .replace(/:/g, '-')
        .replace(/\./g, '-')
        .replace('T', '_')
        .replace('Z', '');

    const dasherName = (dasherInfo.first_name || 'Unknown') + '_' +
                      (dasherInfo.last_name || 'Dasher');

    const safeFileName = dasherName.replace(/[^a-zA-Z0-9_-]/g, '_');
    const fileName = `${safeFileName}_${timestamp}.log`;
    const filePath = path.join(logDir, fileName);

    // Add metadata to the log
    const fullLog = `DASHER INFORMATION LOG
Generated: ${new Date().toLocaleString()}
File: ${fileName}

${formattedOutput}

RAW JSON DATA:
${JSON.stringify(dasherInfo, null, 2)}
`;

    fs.writeFileSync(filePath, fullLog, 'utf8');
    console.log(`✅ Log saved to: ${filePath}`);

    // Also create a summary file for quick reference
    const summaryFile = path.join(logDir, 'SUMMARY.txt');
    const summaryEntry = `${new Date().toLocaleString()} - ${dasherName}: ${dasherInfo.notes || 'No restrictions'}\n`;

    fs.appendFileSync(summaryFile, summaryEntry, 'utf8');

    return filePath;
}

module.exports = { saveDasherLog };