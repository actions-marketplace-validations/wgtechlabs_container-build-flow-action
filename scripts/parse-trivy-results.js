#!/usr/bin/env node
/**
 * Parse Trivy Results Script
 * ===========================
 * Parses Trivy scan results and generates summary with vulnerability counts
 *
 * This script reads the Trivy JSON output, counts vulnerabilities by severity,
 * and sets GitHub Actions outputs for use in workflows and PR comments.
 *
 * Input:
 *   - trivy-image-results.json: Trivy scan results in JSON format
 *
 * Output:
 *   - trivy-scan-summary.json: Summary with vulnerability counts
 *   - GitHub Actions outputs: completed, total, critical, high, medium, low
 */

const fs = require('fs');

/**
 * Set GitHub Actions output using GITHUB_OUTPUT file
 */
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}\n`);
  }
}

/**
 * Parse Trivy results and count vulnerabilities by severity
 */
function parseTrivyResults() {
  try {
    console.log('📊 Parsing Trivy scan results...');

    // Check if results file exists
    if (!fs.existsSync('trivy-image-results.json')) {
      console.warn('⚠️  trivy-image-results.json not found');

      // Write empty summary
      const emptySummary = {
        completed: false,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0
      };

      fs.writeFileSync('trivy-scan-summary.json', JSON.stringify(emptySummary, null, 2));

      // Set outputs
      setOutput('completed', 'false');
      setOutput('total', '0');
      setOutput('critical', '0');
      setOutput('high', '0');
      setOutput('medium', '0');
      setOutput('low', '0');

      return;
    }

    // Read and parse Trivy results
    const resultsContent = fs.readFileSync('trivy-image-results.json', 'utf8');
    const results = JSON.parse(resultsContent);

    // Initialize counters
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };

    // Parse results based on Trivy JSON structure
    if (results.Results && Array.isArray(results.Results)) {
      results.Results.forEach(result => {
        if (result.Vulnerabilities && Array.isArray(result.Vulnerabilities)) {
          result.Vulnerabilities.forEach(vuln => {
            const severity = (vuln.Severity || 'UNKNOWN').toUpperCase();

            switch (severity) {
              case 'CRITICAL':
                counts.critical++;
                break;
              case 'HIGH':
                counts.high++;
                break;
              case 'MEDIUM':
                counts.medium++;
                break;
              case 'LOW':
                counts.low++;
                break;
              default:
                counts.unknown++;
            }
          });
        }
      });
    }

    // Calculate total
    const total = counts.critical + counts.high + counts.medium + counts.low + counts.unknown;

    // Create summary object
    const summary = {
      completed: true,
      total: total,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      unknown: counts.unknown
    };

    // Write summary to file
    fs.writeFileSync('trivy-scan-summary.json', JSON.stringify(summary, null, 2));

    // Set GitHub Actions outputs
    setOutput('completed', 'true');
    setOutput('total', total.toString());
    setOutput('critical', counts.critical.toString());
    setOutput('high', counts.high.toString());
    setOutput('medium', counts.medium.toString());
    setOutput('low', counts.low.toString());

    // Log summary
    console.log('✅ Vulnerability scan summary:');
    console.log(`  Total: ${total}`);
    console.log(`  Critical: ${counts.critical}`);
    console.log(`  High: ${counts.high}`);
    console.log(`  Medium: ${counts.medium}`);
    console.log(`  Low: ${counts.low}`);

    if (counts.unknown > 0) {
      console.log(`  Unknown: ${counts.unknown}`);
    }

  } catch (error) {
    console.error(`❌ Failed to parse Trivy results: ${error.message}`);

    // Set error outputs
    setOutput('completed', 'false');
    setOutput('total', '0');
    setOutput('critical', '0');
    setOutput('high', '0');
    setOutput('medium', '0');
    setOutput('low', '0');

    // Don't fail the action, just log the error
    console.warn('Continuing despite parse error...');
  }
}

// Execute
parseTrivyResults();
