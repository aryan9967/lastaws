const express = require('express');
const multer = require('multer');
const fs = require('fs-extra');
const AWS = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { spawnSync } = require('child_process');
const { analyzeLogFile } = require('./analyzeLogs');

const app = express();
const PORT = 3000;

require('dotenv').config(); // Load environment variables from .env file

AWS.config.update({ region: 'us-east-1' }); // Set your region
const s3 = new AWS.S3();
const ssm = new AWS.SSM();

const BUCKET_NAME = 'malware-analysis-files-aryan-v1';
const EC2_INSTANCE_ID = 'i-03d9912808e1a65a2';

// Make sure uploads and logs directories exist
fs.ensureDirSync('./uploads');
fs.ensureDirSync('./logs');

const storage = multer.diskStorage({
    destination: './uploads',
    filename: (_, file, cb) => cb(null, `${uuidv4()}-${file.originalname}`),
});
const upload = multer({ storage });

async function waitForSSMCommand(commandId, instanceId, timeout = 180000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        const result = await ssm
            .getCommandInvocation({ CommandId: commandId, InstanceId: instanceId })
            .promise();

        console.log(`Command status: ${result.Status}`);
        
        if (result.Status === 'Success') return true;
        if (['Failed', 'Cancelled', 'TimedOut'].includes(result.Status)) {
            console.error('Command output:', result.StandardOutputContent);
            console.error('Command error:', result.StandardErrorContent);
            throw new Error(`SSM command failed with status: ${result.Status}, Error: ${result.StandardErrorContent}`);
        }

        await new Promise((r) => setTimeout(r, 5000)); // Retry every 5s
    }
    throw new Error('SSM command timed out');
}

app.post('/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const filePath = req.file.path;
    const fileName = path.basename(filePath);
    const sanitizedFileName = fileName.replace(/[+]/g, '_'); // Replace potentially problematic characters
    const s3Key = `malware_samples/${sanitizedFileName}`;
    const logZipKey = `logs/${sanitizedFileName}.zip`;
    
    // Create log directories
    const logsDir = path.join(__dirname, 'logs');
    await fs.ensureDir(logsDir);
    
    const localLogZip = path.join(logsDir, `${sanitizedFileName}.zip`);
    const unzipPath = path.join(logsDir, sanitizedFileName.replace('.exe', ''));
    
    console.log(`Local log zip path: ${localLogZip}`);
    console.log(`Unzip path: ${unzipPath}`);

    try {
        // Upload file to S3
        console.log(`[*] Uploading ${fileName} to S3...`);
        await s3
            .upload({
                Bucket: BUCKET_NAME,
                Key: s3Key,
                Body: fs.createReadStream(filePath),
            })
            .promise();
        console.log(`[+] Uploaded ${fileName} to S3`);

        // SSM PowerShell script to analyze the file
        const powershellScript = `
    $ErrorActionPreference = "Stop"
    
    # Create working directory
    $workDir = "C:\\Temp\\MalwareAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    Set-Location -Path $workDir
    
    # Download sample from S3
    Write-Output "Downloading sample from S3"
    aws s3 cp s3://${BUCKET_NAME}/${s3Key} .\\sample.exe
    
    # Ensure Sysmon is running
$sysmonStatus = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
if ($null -eq $sysmonStatus -or $sysmonStatus.Status -ne "Running") {
    Write-Error "Sysmon service is not running"
    exit 1
}

# Clear previous Sysmon logs
Write-Output "Clearing previous Sysmon logs"
wevtutil cl Microsoft-Windows-Sysmon/Operational

# Execute the sample in a controlled environment
Write-Output "Running sample in controlled environment"
Start-Process -FilePath ".\\sample.exe" -WindowStyle Hidden
    
    # Wait for execution and log generation
    Write-Output "Collecting logs"
    Start-Sleep -Seconds 10
    
    # Export Sysmon logs
    wevtutil epl Microsoft-Windows-Sysmon/Operational .\\sysmon_full.evtx
    
    # Package logs
    Write-Output "Packaging logs"
    Compress-Archive -Path .\\sysmon_full.evtx -DestinationPath .\\logs.zip -Force
    
    # Upload to S3
    Write-Output "Uploading logs to S3"
    aws s3 cp .\\logs.zip s3://${BUCKET_NAME}/${logZipKey}
    
    # Clean up
    Set-Location -Path "C:\\Temp"
    Remove-Item -Path $workDir -Recurse -Force
    
    Write-Output "Analysis complete"
  `;
        
        console.log('[*] Sending SSM command to EC2 instance...');
        const { Command } = await ssm
            .sendCommand({
                InstanceIds: [EC2_INSTANCE_ID],
                DocumentName: 'AWS-RunPowerShellScript',
                Parameters: { commands: [powershellScript] },
            })
            .promise();
        const commandId = Command.CommandId;
        console.log(`[+] SSM command sent: ${commandId}`);

        // Wait for command to complete
        await waitForSSMCommand(commandId, EC2_INSTANCE_ID);
        console.log('[+] SSM command completed');

        // Try to fetch log zip from S3
        console.log(`[*] Attempting to download log ZIP from S3 with key: ${logZipKey}`);
        
        try {
            // List objects to verify the log file exists
            const listResult = await s3
                .listObjectsV2({ Bucket: BUCKET_NAME, Prefix: 'logs/' })
                .promise();
            console.log('Available S3 logs:', listResult.Contents.map(f => f.Key));
            
            const data = await s3
                .getObject({ Bucket: BUCKET_NAME, Key: logZipKey })
                .promise();
            
            // Make sure the parent directory exists
            await fs.ensureDir(path.dirname(localLogZip));
                
            // Write the log file
            await fs.writeFile(localLogZip, data.Body);
            console.log(`[+] Log ZIP downloaded to ${localLogZip}`);
            
            // Extract ZIP - ensure unzip directory exists first
            await fs.ensureDir(unzipPath);
            
            console.log(`[*] Extracting ZIP to ${unzipPath}`);
            
            // Check if unzip is available, otherwise use a Node.js solution
            let unzipSuccess = false;
            try {
                const unzip = spawnSync('unzip', [localLogZip, '-d', unzipPath]);
                if (unzip.error) {
                    console.warn(`[!] Unzip command failed: ${unzip.error}, trying alternative extraction`);
                } else {
                    unzipSuccess = true;
                    console.log('[+] Unzip completed successfully');
                }
            } catch (unzipError) {
                console.warn(`[!] Unzip command error: ${unzipError.message}`);
            }
            
            // If unzip command failed, try alternative extraction
            if (!unzipSuccess) {
                console.log('[*] Using Node.js extraction');
                // Use a Node.js solution like decompress or adm-zip if unzip fails
                // This is a stub - you'll need to implement this part with a Node.js zip library
                // For example:
                const AdmZip = require('adm-zip');
                const zip = new AdmZip(localLogZip);
                zip.extractAllTo(unzipPath, true);
                // return res.status(500).json({ error: 'Unzip failed. Please install unzip or add a Node.js zip library.' });
            }
            
            // Analyze logs
            console.log(`[*] Analyzing logs in ${unzipPath}`);
            const analysisResults = await analyzeLogFile(unzipPath);
            console.log(`[+] Analysis result: ${analysisResults.isMalicious ? 'Malicious' : 'Clean'}`);
            console.log(`[+] Maliciousness score: ${(analysisResults.score * 100).toFixed(1)}%`);
            
            // Return detailed results to the client
            res.json({
                fileName: fileName,
                malicious: analysisResults.isMalicious,
                score: analysisResults.score,
                summary: analysisResults.summary,
                significantFeatures: analysisResults.significantFeatures,
                eventCount: analysisResults.eventCount,
                timestamp: analysisResults.timestamp
            });
        } catch (s3Error) {
            console.error('[x] Error downloading or processing logs:', s3Error);
            
            // Check if the logs file exists in S3
            try {
                await s3.headObject({
                    Bucket: BUCKET_NAME,
                    Key: logZipKey
                }).promise();
                console.log(`[!] The file ${logZipKey} exists but couldn't be processed`);
            } catch (headErr) {
                console.error(`[x] The file ${logZipKey} doesn't exist in S3:`, headErr);
            }
            
            throw new Error(`Failed to process logs: ${s3Error.message}`);
        }
        
    } catch (err) {
        console.error('[x] Error during analysis:', err);
        res.status(500).json({ error: err.message || 'Malware analysis failed' });
    } finally {
        // Cleanup uploaded file and any temporary files
        try {
            await fs.remove(filePath);
            console.log(`[+] Cleaned up uploaded file: ${filePath}`);
            
            // Attempt to clean up temporary files if they exist
            if (await fs.pathExists(localLogZip)) {
                await fs.remove(localLogZip);
                console.log(`[+] Cleaned up log zip: ${localLogZip}`);
            }
            
            if (await fs.pathExists(unzipPath)) {
                await fs.remove(unzipPath);
                console.log(`[+] Cleaned up unzip directory: ${unzipPath}`);
            }
        } catch (cleanupErr) {
            console.warn('[!] Error during cleanup:', cleanupErr);
        }
    }
});

// Add a simple status endpoint
app.get('/status', (req, res) => {
    res.json({ status: 'online' });
});

app.listen(PORT, () => {
    console.log(`🚀 Server listening at http://localhost:${PORT}`);
});