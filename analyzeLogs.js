const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const xml2js = require('xml2js');

/**
 * Analyzes Sysmon logs to determine if a file is malicious
 * @param {string} logDir - Directory containing extracted log files
 * @returns {Promise<Object>} - Analysis results including maliciousness score and details
 */
async function analyzeLogFile(logDir) {
  console.log(`[*] Analyzing logs in ${logDir}`);
  
  // Find the Sysmon EVTX file
  const evtxPath = path.join(logDir, 'sysmon_full.evtx');
  if (!await fs.pathExists(evtxPath)) {
    throw new Error('Sysmon log file not found');
  }
  
  // Parse EVTX file - first convert to XML using PowerShell (on Windows)
  // or use a temporary XML file approach
  const events = await parseEvtxFile(evtxPath);
  console.log(`[+] Parsed ${events.length} Sysmon events`);
  
  // Extract features from events
  const features = extractFeatures(events);
  
  // Score the features to determine maliciousness
  const score = scoreMaliciousness(features);
  
  // Get the most significant features for reporting
  const significantFeatures = getSignificantFeatures(features);
  
  // Determine if the score exceeds our threshold
  const isMalicious = score > 0.7; // 70% confidence threshold
  
  // Create a summary of detection results
  const summary = createDetectionSummary(events, features, score);
  
  return {
    isMalicious,
    score,
    features,
    significantFeatures,
    summary,
    eventCount: events.length,
    timestamp: new Date().toISOString()
  };
}

/**
 * Parse an EVTX file into an array of events
 * First converts EVTX to XML format, then parses the XML
 * @param {string} filePath - Path to the EVTX file
 * @returns {Promise<Array>} - Array of parsed events
 */
async function parseEvtxFile(filePath) {
  try {
    // Approach 1: For Windows environments - use PowerShell to convert EVTX to XML
    const xmlPath = filePath + '.xml';
    
    return new Promise((resolve, reject) => {
      // Create a PowerShell command to export EVTX to XML format
      const powershellCmd = `Get-WinEvent -Path "${filePath}" -Oldest | Export-Clixml -Path "${xmlPath}"`;
      
      exec(`powershell -Command "${powershellCmd}"`, async (error, stdout, stderr) => {
        if (error) {
          console.warn('PowerShell approach failed, falling back to binary parsing');
          // If PowerShell export fails, fall back to our manual binary parsing method
          const events = await manualEvtxParse(filePath);
          return resolve(events);
        }
        
        // Read and parse the exported XML
        try {
          const xmlContent = await fs.readFile(xmlPath, 'utf8');
          const parser = new xml2js.Parser({ explicitArray: false });
          parser.parseString(xmlContent, (err, result) => {
            if (err) {
              reject(new Error(`XML parsing error: ${err.message}`));
            } else {
              // Process the XML data into our desired event format
              const events = processXmlEvents(result);
              
              // Clean up temporary XML file
              fs.remove(xmlPath).catch(e => console.warn('Failed to remove temporary XML file:', e));
              
              resolve(events);
            }
          });
        } catch (xmlErr) {
          reject(new Error(`Failed to process XML file: ${xmlErr.message}`));
        }
      });
    });
  } catch (err) {
    console.error('[x] Error parsing EVTX file:', err);
    throw new Error(`Failed to parse EVTX file: ${err.message}`);
  }
}

/**
 * Manual binary parsing approach for EVTX files when PowerShell isn't available
 * @param {string} filePath - Path to the EVTX file
 * @returns {Promise<Array>} - Array of parsed events
 */
async function manualEvtxParse(filePath) {
  console.log('[*] Using manual binary parsing for EVTX file');
  
  try {
    // Read the EVTX file as binary
    const buffer = await fs.readFile(filePath);
    
    // EVTX files have a specific header structure
    // We'll need to extract chunks and records
    
    // Basic structure of an EVTX file:
    // - File header (4KB)
    // - Multiple chunks (64KB each)
    // - Each chunk contains multiple event records
    
    // This is a simplified version - a complete parser would be much more complex
    const events = [];
    
    // Check if the file signature is valid
    if (buffer.toString('utf8', 0, 8) !== 'ElfFile\0') {
      throw new Error('Invalid EVTX file signature');
    }
    
    // Get the number of chunks
    const chunkCount = buffer.readUInt16LE(0x10);
    console.log(`[*] Detected ${chunkCount} chunks in EVTX file`);
    
    // Process each chunk
    // This is a very simplified approach, actual EVTX parsing is more complex
    for (let i = 0; i < chunkCount; i++) {
      const chunkOffset = 0x1000 + (i * 0x10000); // Starting at 4KB, each chunk is 64KB
      
      // Skip chunks that don't fit in the buffer
      if (chunkOffset + 0x10000 > buffer.length) {
        continue;
      }
      
      // Extract event data from the chunk
      const extractedEvents = extractEventsFromChunk(buffer, chunkOffset);
      events.push(...extractedEvents);
    }
    
    // If no events could be parsed, try a simplified parsing approach
    if (events.length === 0) {
      console.log('[*] No events extracted using chunk approach, using simplified parsing');
      
      // Search for XML event fragments within the file
      // This is a fallback approach and may extract partial events
      const xmlEvents = extractXmlEventFragments(buffer);
      events.push(...xmlEvents);
    }
    
    console.log(`[+] Extracted ${events.length} events using manual parsing`);
    return events;
  } catch (err) {
    console.error('[x] Manual EVTX parsing failed:', err);
    // Return an empty array if parsing fails
    return [];
  }
}

/**
 * Extract event data from an EVTX chunk
 * @param {Buffer} buffer - The full file buffer
 * @param {number} offset - The offset of the chunk
 * @returns {Array} - Array of events extracted from the chunk
 */
function extractEventsFromChunk(buffer, offset) {
  const events = [];
  
  try {
    // Check chunk signature
    if (buffer.toString('utf8', offset, offset + 8) !== 'ElfChnk\0') {
      return events; // Invalid chunk, skip
    }
    
    // Read the first record offset
    const firstRecordOffset = buffer.readUInt32LE(offset + 0x28);
    
    // Read the last record offset 
    const lastRecordOffset = buffer.readUInt32LE(offset + 0x2C);
    
    // Read the number of records in this chunk
    const recordCount = buffer.readUInt32LE(offset + 0x30);
    
    console.log(`[*] Chunk: first record at ${firstRecordOffset}, last at ${lastRecordOffset}, count: ${recordCount}`);
    
    if (recordCount > 0 && recordCount < 10000) { // Sanity check
      let currentOffset = offset + firstRecordOffset;
      
      for (let i = 0; i < recordCount && currentOffset < offset + 0x10000; i++) {
        // Read the size of the record
        const recordSize = buffer.readUInt32LE(currentOffset);
        
        if (recordSize < 8 || recordSize > 0x10000) {
          // Invalid record size, move to the next position
          currentOffset += 8;
          continue;
        }
        
        // Try to extract XML from the record data
        try {
          const recordData = buffer.slice(currentOffset + 8, currentOffset + recordSize);
          const xmlData = extractXmlFromRecord(recordData);
          
          if (xmlData) {
            events.push(parseEventXml(xmlData));
          }
        } catch (e) {
          // Skip this record
        }
        
        // Move to the next record
        currentOffset += recordSize;
      }
    }
  } catch (err) {
    console.warn(`[!] Error processing chunk at offset ${offset}:`, err);
  }
  
  return events;
}

/**
 * Extract XML data from a record's binary data
 * @param {Buffer} recordData - Binary data of a record
 * @returns {string|null} - Extracted XML string or null if not found
 */
function extractXmlFromRecord(recordData) {
  // This is a simplified approach - real implementation would need to
  // handle the BinXML format used in EVTX files
  
  // Look for XML start marker
  let startIdx = -1;
  for (let i = 0; i < recordData.length - 5; i++) {
    if (recordData[i] === 60 && recordData[i+1] === 63 && // <?
        recordData[i+2] === 120 && recordData[i+3] === 109 && // xm
        recordData[i+4] === 108) { // l
      startIdx = i;
      break;
    }
  }
  
  if (startIdx === -1) return null;
  
  // Extract the XML part
  try {
    const xmlPart = recordData.slice(startIdx).toString('utf16le');
    return xmlPart;
  } catch (e) {
    return null;
  }
}

/**
 * Fall back method: search for XML fragments in the buffer
 * @param {Buffer} buffer - The full file buffer
 * @returns {Array} - Array of events extracted from XML fragments
 */
function extractXmlEventFragments(buffer) {
  const events = [];
  
  // Convert buffer to string and look for Event tags
  const content = buffer.toString('utf16le');
  const eventPattern = /<Event[^>]*>[\s\S]*?<\/Event>/g;
  
  let match;
  while ((match = eventPattern.exec(content)) !== null) {
    try {
      const xmlContent = match[0];
      const event = parseEventXml(xmlContent);
      if (event) {
        events.push(event);
      }
    } catch (e) {
      // Skip this fragment
    }
  }
  
  return events;
}

/**
 * Parse an XML event string into our event object structure
 * @param {string} xmlString - XML event data
 * @returns {Object} - Parsed event object
 */
function parseEventXml(xmlString) {
  // This is a simplified parser for XML event data
  // In a real implementation, you'd use a proper XML parser
  
  // Extract event ID
  const eventIdMatch = xmlString.match(/<EventID[^>]*>(\d+)<\/EventID>/);
  const eventId = eventIdMatch ? parseInt(eventIdMatch[1]) : 0;
  
  // Extract event data elements
  const dataItems = {};
  const dataPattern = /<Data Name="([^"]+)"[^>]*>([^<]+)<\/Data>/g;
  
  let dataMatch;
  while ((dataMatch = dataPattern.exec(xmlString)) !== null) {
    dataItems[dataMatch[1]] = dataMatch[2];
  }
  
  return {
    Event: {
      System: {
        EventID: eventId
      },
      EventData: {
        Data: Object.entries(dataItems).map(([name, value]) => ({
          Name: name,
          Text: value
        }))
      }
    }
  };
}

/**
 * Process XML events into our standard event format
 * @param {Object} xmlResult - Result from xml2js parsing
 * @returns {Array} - Array of standardized event objects
 */
function processXmlEvents(xmlResult) {
  const events = [];
  
  try {
    // Handle the structure produced by Export-Clixml
    const objects = xmlResult?.Objs?.Obj || [];
    const eventArray = Array.isArray(objects) ? objects : [objects];
    
    for (const eventObj of eventArray) {
      // Extract properties from the PowerShell XML format
      const props = eventObj?.Props?.S || [];
      const eventData = {};
      
      // Convert the properties array to our format
      if (Array.isArray(props)) {
        for (const prop of props) {
          if (prop?.N && (prop?._ || prop?.$)) {
            eventData[prop.N] = prop._ || prop.$;
          }
        }
      }
      
      // Create an event object in our standard format
      events.push({
        Event: {
          System: {
            EventID: eventData.Id || 0
          },
          EventData: {
            Data: Object.entries(eventData).map(([name, value]) => ({
              Name: name,
              Text: value
            }))
          }
        }
      });
    }
  } catch (err) {
    console.error('[x] Error processing XML events:', err);
  }
  
  return events;
}

/**
 * Extract malware detection features from Sysmon events
 * @param {Array} events - Array of Sysmon events
 * @returns {Object} - Extracted features
 */
function extractFeatures(events) {
  const features = {
    // Process Creation (Event ID 1)
    processCreations: 0,
    suspiciousProcesses: 0,
    suspiciousProcessList: new Set(),
    
    // File Creation (Event ID 11)
    fileCreations: 0,
    executableCreations: 0,
    suspiciousFileLocations: 0,
    tempDirAccess: 0,
    createdFiles: [],
    
    // Network Connections (Event ID 3)
    networkConnections: 0,
    suspiciousConnections: 0,
    connectionDetails: [],
    
    // Registry Operations (Event IDs 12, 13, 14)
    registryOperations: 0,
    autoRunModifications: 0,
    suspiciousRegistryKeys: [],
    
    // WMI Activity (Event IDs 19, 20, 21)
    wmiActivity: 0,
    
    // Unusual Behavior Patterns
    shellCodeExecution: 0,
    processInjection: 0,
    injectionAttempts: [],
    privilegeEscalation: 0,
    defenseMechanismTampering: 0,
    antiAnalysisAttempts: []
  };
  
  // Process each event
  for (const event of events) {
    // Extract the Event data from the structure
    const eventObj = event?.Event || {};
    const eventSystem = eventObj?.System || {};
    const eventId = parseInt(eventSystem?.EventID || 0);
    const eventData = eventObj?.EventData?.Data || [];
    
    // Convert eventData array to an easy-to-use object
    const data = {};
    if (Array.isArray(eventData)) {
      eventData.forEach(item => {
        if (item.Name && item.Text) {
          data[item.Name] = item.Text;
        } else if (item['@Name'] && item['#text']) {
          data[item['@Name']] = item['#text'];
        }
      });
    } else if (eventData && typeof eventData === 'object') {
      // Some parsers might return data directly as an object
      for (const key in eventData) {
        if (eventData[key]?.Text) {
          data[key] = eventData[key].Text;
        }
      }
    }
    
    // Process Creation (Event ID 1)
    if (eventId === 1) {
      features.processCreations++;
      
      // Check for suspicious process names
      const suspiciousProcessNames = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 
        'regsvr32.exe', 'mshta.exe', 'rundll32.exe'
      ];
      
      const suspiciousCommandArgs = [
        '-enc', '-w hidden', 'downloadstring', 'iex', 'invoke-expression',
        'bypass', '-nop', '-noni', '-windowstyle hidden', '/c '
      ];
      
      if (data.Image && suspiciousProcessNames.some(proc => data.Image.toLowerCase().includes(proc))) {
        features.suspiciousProcesses++;
        features.suspiciousProcessList.add(data.Image);
      }
      
      if (data.CommandLine && suspiciousCommandArgs.some(arg => 
          data.CommandLine.toLowerCase().includes(arg))) {
        features.suspiciousProcesses++;
        features.suspiciousProcessList.add(`${data.Image || 'Unknown'} (Suspicious Args: ${data.CommandLine})`);
      }
    }
    
    // File Creation (Event ID 11)
    if (eventId === 11) {
      features.fileCreations++;
      
      const executableExtensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta'];
      if (data.TargetFilename && executableExtensions.some(ext => 
          data.TargetFilename.toLowerCase().endsWith(ext))) {
        features.executableCreations++;
        features.createdFiles.push({
          path: data.TargetFilename,
          type: 'executable',
          process: data.Image
        });
      }
      
      if (data.TargetFilename) {
        const suspiciousLocations = ['\\temp\\', '\\appdata\\', '\\public\\', '\\programdata\\'];
        if (suspiciousLocations.some(loc => data.TargetFilename.toLowerCase().includes(loc))) {
          features.suspiciousFileLocations++;
        }
        
        if (data.TargetFilename.toLowerCase().includes('\\temp\\')) {
          features.tempDirAccess++;
        }
        
        // Add file creation info
        features.createdFiles.push({
          path: data.TargetFilename,
          process: data.Image
        });
      }
    }
    
    // Network Connection (Event ID 3)
    if (eventId === 3) {
      features.networkConnections++;
      
      // Check for suspicious connections (non-standard ports, unusual processes making connections)
      const nonBrowserProcesses = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 
        'rundll32.exe', 'regsvr32.exe'
      ];
      
      let isSuspicious = false;
      
      if (data.Image && nonBrowserProcesses.some(proc => data.Image.toLowerCase().includes(proc))) {
        features.suspiciousConnections++;
        isSuspicious = true;
      }
      
      // Unusual destination ports (other than common ones)
      const commonPorts = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995];
      if (data.DestinationPort && !commonPorts.includes(parseInt(data.DestinationPort))) {
        features.suspiciousConnections += 0.5;
        isSuspicious = true;
      }
      
      // Record connection details
      features.connectionDetails.push({
        sourceProcess: data.Image,
        sourceIp: data.SourceIp,
        sourcePort: data.SourcePort,
        destinationIp: data.DestinationIp,
        destinationPort: data.DestinationPort,
        suspicious: isSuspicious
      });
    }
    
    // Registry Operations (Event IDs 12, 13, 14)
    if ([12, 13, 14].includes(eventId)) {
      features.registryOperations++;
      
      // Check for autorun registry keys
      const autorunKeys = [
        'run', 'runonce', 'winlogon', 'userinit', 'shell', 'startup',
        'currentversion\\explorer', 'appinit_dlls'
      ];
      
      if (data.TargetObject && autorunKeys.some(key => 
          data.TargetObject.toLowerCase().includes(key))) {
        features.autoRunModifications++;
        features.suspiciousRegistryKeys.push({
          key: data.TargetObject,
          operation: eventId === 12 ? 'create' : (eventId === 13 ? 'set' : 'delete'),
          process: data.Image,
          details: data.Details || ''
        });
      }
    }
    
    // WMI Activity (Event IDs 19, 20, 21)
    if ([19, 20, 21].includes(eventId)) {
      features.wmiActivity++;
    }
    
    // Detect Process Injection (Event ID 8 - CreateRemoteThread)
    if (eventId === 8) {
      features.processInjection++;
      features.injectionAttempts.push({
        sourceProcess: data.SourceImage,
        targetProcess: data.TargetImage,
        startAddress: data.StartAddress,
        startModule: data.StartModule
      });
    }
    
    // Detect defense mechanism tampering
    if (data.Image && data.CommandLine) {
      const defenseTamperingPatterns = [
        'taskkill /f /im', 'net stop', 'sc stop', 
        'reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'uninstall', 'defender', 'firewall', 'smartscreen'
      ];
      
      if (defenseTamperingPatterns.some(pattern => 
          data.CommandLine.toLowerCase().includes(pattern))) {
        features.defenseMechanismTampering++;
      }
    }
    
    // Check for anti-analysis techniques
    const antiAnalysisPatterns = [
      'sleep', 'waitfor', 'timeout', 'ping -n', 'virtualbox', 'vmware',
      'sandboxie', 'wireshark', 'processexplorer', 'procmon', 'tcpview'
    ];
    
    if (data.CommandLine && antiAnalysisPatterns.some(pattern => 
        data.CommandLine.toLowerCase().includes(pattern))) {
      features.antiAnalysisAttempts.push({
        process: data.Image,
        commandLine: data.CommandLine
      });
    }
  }
  
  // Convert Set to Array for easier handling later
  features.suspiciousProcessList = Array.from(features.suspiciousProcessList);
  
  return features;
}

/**
 * Score the extracted features to determine maliciousness
 * @param {Object} features - Extracted features
 * @returns {number} - Maliciousness score between 0 and 1
 */
function scoreMaliciousness(features) {
  let score = 0;
  let maxScore = 0;
  
  // Weighted scoring for different indicators
  const weights = {
    suspiciousProcesses: 0.5,
    executableCreations: 0.6,
    suspiciousFileLocations: 0.4,
    suspiciousConnections: 0.7,
    autoRunModifications: 0.8,
    processInjection: 0.9,
    wmiActivity: 0.3,
    defenseMechanismTampering: 0.9,
    antiAnalysisAttempts: 0.7
  };
  
  // Calculate weighted score
  for (const [feature, weight] of Object.entries(weights)) {
    if (typeof features[feature] === 'number') {
      // For numeric values, add the weighted value
      score += features[feature] * weight;
      // Increase the max possible score
      maxScore += Math.max(5, features[feature] * 2) * weight;
    } else if (Array.isArray(features[feature])) {
      // For arrays, add the weighted length
      score += features[feature].length * weight;
      // Increase the max possible score
      maxScore += Math.max(5, features[feature].length * 2) * weight;
    }
  }
  
  // Normalize the score to be between 0 and 1
  return maxScore > 0 ? Math.min(score / maxScore, 1) : 0;
}

/**
 * Get the most significant features for reporting
 * @param {Object} features - Extracted features
 * @returns {Object} - Significant features for reporting
 */
function getSignificantFeatures(features) {
  const significant = {};
  
  // Include suspicious process information
  if (features.suspiciousProcesses > 0) {
    significant.suspiciousProcesses = {
      count: features.suspiciousProcesses,
      processes: features.suspiciousProcessList.slice(0, 10) // Limit to top 10
    };
  }
  
  // Include suspicious file creations
  if (features.executableCreations > 0) {
    significant.executableCreations = {
      count: features.executableCreations,
      examples: features.createdFiles
        .filter(f => f.type === 'executable')
        .slice(0, 5) // Limit to 5 examples
    };
  }
  
  // Include suspicious network connections
  if (features.suspiciousConnections > 0) {
    significant.suspiciousConnections = {
      count: Math.floor(features.suspiciousConnections),
      examples: features.connectionDetails
        .filter(c => c.suspicious)
        .slice(0, 5) // Limit to 5 examples
    };
  }
  
  // Include registry modifications
  if (features.autoRunModifications > 0) {
    significant.autoRunModifications = {
      count: features.autoRunModifications,
      keys: features.suspiciousRegistryKeys.slice(0, 5) // Limit to 5 examples
    };
  }
  
  // Include process injection attempts
  if (features.processInjection > 0) {
    significant.processInjection = {
      count: features.processInjection,
      examples: features.injectionAttempts.slice(0, 3) // Limit to 3 examples
    };
  }
  
  // Include defense mechanism tampering
  if (features.defenseMechanismTampering > 0) {
    significant.defenseMechanismTampering = {
      count: features.defenseMechanismTampering
    };
  }
  
  // Include anti-analysis techniques
  if (features.antiAnalysisAttempts.length > 0) {
    significant.antiAnalysisAttempts = {
      count: features.antiAnalysisAttempts.length,
      examples: features.antiAnalysisAttempts.slice(0, 3) // Limit to 3 examples
    };
  }
  
  return significant;
}

/**
 * Create a summary of the detection results
 * @param {Array} events - Parsed events
 * @param {Object} features - Extracted features
 * @param {number} score - Maliciousness score
 * @returns {string} - Summary text
 */
function createDetectionSummary(events, features, score) {
  const summaryParts = [];
  
  // Overall assessment
  const threatLevel = score < 0.3 ? 'Low' : (score < 0.7 ? 'Medium' : 'High');
  summaryParts.push(`Threat Level: ${threatLevel} (Score: ${(score * 100).toFixed(1)}%)`);
  summaryParts.push(`Analyzed ${events.length} events`);
  
  // Summarize the key indicators
  if (features.suspiciousProcesses > 0) {
    summaryParts.push(`Detected ${features.suspiciousProcesses} suspicious process executions`);
  }
  
  if (features.executableCreations > 0) {
    summaryParts.push(`Created ${features.executableCreations} executable files`);
  }
  
  if (features.suspiciousConnections > 0) {
    summaryParts.push(`Established ${Math.floor(features.suspiciousConnections)} suspicious network connections`);
  }
  
  if (features.autoRunModifications > 0) {
    summaryParts.push(`Modified ${features.autoRunModifications} autorun registry keys`);
  }
  
  if (features.processInjection > 0) {
    summaryParts.push(`Detected ${features.processInjection} process injection attempts`);
  }
  
  if (features.defenseMechanismTampering > 0) {
    summaryParts.push(`Attempted to tamper with defense mechanisms ${features.defenseMechanismTampering} times`);
  }
  
  return summaryParts.join('\n');
}

module.exports = {
  analyzeLogFile
};