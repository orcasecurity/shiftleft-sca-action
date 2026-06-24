const core = require("@actions/core");

function wrapWords(input, maxLineLength = 80) {
  const words = input.split(/\s+/);
  const lines = [];
  let currentLine = "";

  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (currentLine.length + word.length > maxLineLength) {
      lines.push(currentLine.trim());
      currentLine = "";
    }
    currentLine += (currentLine ? " " : "") + word;
  }

  if (currentLine) {
    lines.push(currentLine.trim());
  }

  return lines.join("\n");
}

function getVulnDetails(vulnerability) {
  let description = [`Severity: ${vulnerability.severity}`];
  if (vulnerability.cvss_v2_score) {
    description.push(`CVSS2 Score: ${vulnerability.cvss_v2_score}`);
  }
  if (vulnerability.cvss_v3_score) {
    description.push(`CVSS3 Score: ${vulnerability.cvss_v3_score}`);
  }
  description.push(`Installed version: ${vulnerability["installed_version"]}`);
  let fixedVersion = vulnerability["fixed_version"];
  if (fixedVersion) {
    description.push(`Fixed version: ${fixedVersion}`);
  }
  return description.join("\n");
}

function getLicenseDetails(license) {
  let details = [];
  details.push(`Package Full Name: ${license["package_name"]}`);
  details.push(`Package Version: ${license["installed_version"]}`);
  if (license.control && license.control["license_category"]) {
    details.push(`License Category: ${license.control["license_category"]}`);
  }
  if (license.control && license.control["url"]) {
    details.push(`SPDX URL: ${license.control["url"]}`);
  }
  if (license["description"]) {
    details.push(`\nDescription:\n${wrapWords(license["description"])}`);
  }
  const recommendation =
    "This package uses an unauthorized license; evaluate its necessity, " +
    "review the license terms, and either replace it with a compliant alternative, " +
    "isolate its usage to reduce risk, or escalate for legal exception if strictly required.";
  details.push(`\nRecommendation:\n${wrapWords(recommendation)}`);
  return details.join("\n");
}

function extractVulnerability(results, annotations) {
  for (const targetVulns of results.vulnerabilities || []) {
    for (const vulnerability of targetVulns.vulnerabilities || []) {
      const location = vulnerability.location || {};
      annotations.push({
        file: targetVulns["target"],
        startLine: location["start_line"] || 1,
        endLine: location["end_line"] || 1,
        priority: vulnerability["severity"],
        status: vulnerability.status_summary
          ? vulnerability.status_summary["status"]
          : "UNKNOWN",
        title: `${vulnerability["pkg_name"]} (${vulnerability["vulnerability_id"]})`,
        details: getVulnDetails(vulnerability),
      });
    }
  }
}

const MALICIOUS_DETAIL_FIELDS = [
  { key: "package_name", label: "Package" },
  { key: "version", label: "Installed Version" },
  { key: "fixed_version", label: "Fixed Version" },
  { key: "target_type", label: "Type" },
  { key: "osv_id", label: "OSV ID" },
];

function getMaliciousDetails(issue) {
  const lines = MALICIOUS_DETAIL_FIELDS.filter(({ key }) => issue[key]).map(
    ({ key, label }) => `${label}: ${issue[key]}`,
  );
  if (issue.affected_ranges?.length) {
    lines.push(`Affected Ranges: ${issue.affected_ranges.join(", ")}`);
  }
  return lines.join("\n");
}

function extractMaliciousPackages(results, annotations) {
  const issues = results.results?.malicious_packages?.issues || [];
  for (const issue of issues) {
    const location = issue.location || {};
    annotations.push({
      file: issue["target"],
      startLine: location["start_line"] || 1,
      endLine: location["end_line"] || 1,
      priority: issue["priority"] || "HIGH",
      status: issue["status"] || "FAILED",
      title: `Malicious package: ${issue["package_name"]}`,
      details: getMaliciousDetails(issue),
    });
  }
}

function extractLicense(results, annotations) {
  const licenses = results.results?.licenses?.issues || [];
  for (const license of licenses) {
    const location = license.location || {};
    annotations.push({
      file: license["target"],
      startLine: location["start_line"] || 1,
      endLine: location["end_line"] || 1,
      priority: license["priority"] || "MEDIUM",
      status: license["status"] || "FAILED",
      title: license["title"] || `License issue for ${license["package_name"]}`,
      details: getLicenseDetails(license),
    });
  }
}

function extractAnnotations(results) {
  let annotations = [];
  extractVulnerability(results, annotations);
  extractMaliciousPackages(results, annotations);
  extractLicense(results, annotations);
  return annotations;
}

function annotateChangesWithResults(results) {
  const annotations = extractAnnotations(results);
  annotations.forEach((annotation) => {
    let annotationProperties = {
      title: annotation.title,
      startLine: annotation.startLine,
      endLine: annotation.endLine,
      file: annotation.file,
    };
    if (annotation.status === "FAILED") {
      core.error(annotation.details, annotationProperties);
    } else {
      core.warning(annotation.details, annotationProperties);
    }
  });
}

module.exports = {
  annotateChangesWithResults,
};
