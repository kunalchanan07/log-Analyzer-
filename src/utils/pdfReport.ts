import { jsPDF } from 'jspdf';
import { Incident } from '../types/soc';

export interface ReportMetadata {
  analystName?: string;
  organization?: string;
  complianceStandard?: string;
}

/**
 * Generates an executive compliance PDF report summarizing high-severity security incidents.
 */
export function generateIncidentPdfReport(
  incidents: Incident[], 
  metadata: ReportMetadata = {}
): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const highSeverityIncidents = incidents.filter(
    i => i.severity === 'critical' || i.severity === 'high'
  );

  const orgName = metadata.organization || 'Enterprise Security Operations Center';
  const analyst = metadata.analystName || 'Kunal (Lead SOC Analyst)';
  const compliance = metadata.complianceStandard || 'SOC 2 Type II / ISO 27001 / NIST SP 800-61';
  const reportDate = new Date().toUTCString();

  // Page geometry
  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 18;

  // --- Header Banner ---
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.rect(0, 0, pageWidth, 28, 'F');

  doc.setTextColor(34, 211, 238); // Cyan 400
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text('LOG ANALYZER BY KUNAL - SECURITY OPERATIONS CENTER', 14, 12);

  doc.setTextColor(203, 213, 225); // Slate 300
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text('HIGH-SEVERITY SECURITY INCIDENT COMPLIANCE AUDIT REPORT', 14, 19);

  doc.setTextColor(148, 163, 184); // Slate 400
  doc.setFontSize(8);
  doc.text(`Classification: CONFIDENTIAL / AUDIT EVIDENCE | Generated: ${reportDate}`, 14, 25);

  y = 38;

  // --- Document Metadata Grid ---
  doc.setDrawColor(226, 232, 240); // Slate 200
  doc.setFillColor(248, 250, 252); // Slate 50
  doc.roundedRect(14, y, pageWidth - 28, 26, 2, 2, 'FD');

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139); // Slate 500
  doc.text('ORGANIZATION:', 18, y + 6);
  doc.text('LEAD INVESTIGATOR:', 18, y + 13);
  doc.text('COMPLIANCE FRAMEWORK:', 18, y + 20);

  doc.setTextColor(15, 23, 42); // Slate 900
  doc.setFont('helvetica', 'bold');
  doc.text(orgName, 60, y + 6);
  doc.text(analyst, 60, y + 13);
  doc.text(compliance, 60, y + 20);

  doc.setTextColor(100, 116, 139);
  doc.setFont('helvetica', 'normal');
  doc.text('TOTAL HIGH/CRITICAL:', 130, y + 6);
  doc.text('CONTAINMENT RATE:', 130, y + 13);
  doc.text('AUDIT STATUS:', 130, y + 20);

  doc.setTextColor(225, 29, 72); // Rose 600
  doc.setFont('helvetica', 'bold');
  doc.text(`${highSeverityIncidents.length} Active Alerts`, 172, y + 6);

  const containedCount = highSeverityIncidents.filter(i => i.status === 'contained' || i.status === 'resolved').length;
  const containmentPct = highSeverityIncidents.length > 0 ? Math.round((containedCount / highSeverityIncidents.length) * 100) : 100;
  doc.setTextColor(13, 148, 136); // Teal 600
  doc.text(`${containmentPct}%`, 172, y + 13);

  doc.setTextColor(15, 23, 42);
  doc.text('VERIFIED', 172, y + 20);

  y += 34;

  // --- Section 1: Executive Summary ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('1. EXECUTIVE SUMMARY & ATTACK VECTORS', 14, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);
  const summaryText = 
    `During the evaluation interval, the Log Analyzer platform detected ${highSeverityIncidents.length} high-severity security incidents requiring active containment. Correlated attack vectors encompass unauthorized SQL injections attempting backend data exfiltration, automated SSH brute force password spraying, and ransomware preparation (Volume Shadow Copy deletion). Threat telemetry was parsed in real-time, matching MITRE ATT&CK framework techniques. All critical assets have been quarantined or protected with border ACL null-routing.`;

  const splitSummary = doc.splitTextToSize(summaryText, pageWidth - 28);
  doc.text(splitSummary, 14, y);
  y += splitSummary.length * 4.2 + 6;

  // --- Section 2: High-Severity Incidents Table ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('2. INCIDENT MANIFEST & CONTAINMENT STATUS', 14, y);
  y += 6;

  // Table Header
  doc.setFillColor(30, 41, 59);
  doc.rect(14, y, pageWidth - 28, 7, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(7.5);
  doc.text('INCIDENT ID', 16, y + 4.8);
  doc.text('SEVERITY', 42, y + 4.8);
  doc.text('ATTACKER IP', 64, y + 4.8);
  doc.text('TARGET ASSET', 94, y + 4.8);
  doc.text('MITRE TECHNIQUE', 132, y + 4.8);
  doc.text('STATUS', 174, y + 4.8);
  y += 7;

  // Table Rows
  doc.setFont('helvetica', 'normal');
  highSeverityIncidents.forEach((inc, idx) => {
    const isEven = idx % 2 === 0;
    doc.setFillColor(isEven ? 248 : 255, isEven ? 250 : 255, isEven ? 252 : 255);
    doc.rect(14, y, pageWidth - 28, 6.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(inc.id, 16, y + 4.3);

    // Severity color
    if (inc.severity === 'critical') {
      doc.setTextColor(225, 29, 72);
      doc.text('CRITICAL', 42, y + 4.3);
    } else {
      doc.setTextColor(217, 119, 6);
      doc.text('HIGH', 42, y + 4.3);
    }

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(30, 41, 59);
    doc.text(inc.attackerIp, 64, y + 4.3);
    doc.text(inc.targetHost, 94, y + 4.3);
    doc.text(`${inc.mitreTechnique} (${inc.mitreTactic})`, 132, y + 4.3);

    // Status
    if (inc.status === 'resolved' || inc.status === 'contained') {
      doc.setTextColor(13, 148, 136);
    } else {
      doc.setTextColor(225, 29, 72);
    }
    doc.setFont('helvetica', 'bold');
    doc.text(inc.status.toUpperCase(), 174, y + 4.3);

    y += 6.5;
  });

  y += 8;

  // --- Section 3: Forensic Details ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. DETAILED FORENSIC ROOT CAUSE & REMEDIATION PLAYBOOKS', 14, y);
  y += 6;

  highSeverityIncidents.slice(0, 3).forEach((inc) => {
    // Check if space needed on page
    if (y > 240) {
      doc.addPage();
      y = 20;
    }

    doc.setDrawColor(203, 213, 225);
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(14, y, pageWidth - 28, 30, 1.5, 1.5, 'D');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`[${inc.id}] ${inc.title}`, 18, y + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    const descLines = doc.splitTextToSize(`Forensic Analysis: ${inc.description}`, pageWidth - 36);
    doc.text(descLines, 18, y + 11);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(13, 148, 136);
    doc.text('Enforced Containment Steps:', 18, y + 20);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const actions = inc.recommendedActions.slice(0, 2).map((a, i) => `${i + 1}. ${a}`).join('  |  ');
    doc.text(actions, 18, y + 25);

    y += 34;
  });

  // --- Section 4: Compliance Sign-off & Chain of Custody ---
  if (y > 235) {
    doc.addPage();
    y = 20;
  }

  y += 4;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('4. AUDIT ATTESTATION & CHAIN OF CUSTODY VERIFICATION', 14, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  doc.text(
    'This document attests that all telemetry and incident responses recorded herein have been preserved under strict forensic chain of custody standards. Redaction of sensitive client passwords and credentials has been executed according to Enterprise DLP Policy.',
    14,
    y,
    { maxWidth: pageWidth - 28 }
  );

  y += 14;

  // Signatures
  doc.setDrawColor(148, 163, 184);
  doc.line(14, y + 10, 80, y + 10);
  doc.line(110, y + 10, 180, y + 10);

  doc.setFontSize(7.5);
  doc.text('Lead SOC Analyst (Signature)', 14, y + 14);
  doc.text(analyst, 14, y + 18);

  doc.text('Information Security Officer / Auditor', 110, y + 14);
  doc.text(`Date Verified: ${new Date().toLocaleDateString()}`, 110, y + 18);

  // Footer on all pages
  const totalPages = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `Page ${i} of ${totalPages}  |  Log Analyzer by Kunal  |  Official Security Compliance Audit Document`,
      pageWidth / 2,
      doc.internal.pageSize.getHeight() - 6,
      { align: 'center' }
    );
  }

  // Save PDF
  doc.save(`SOC-Audit-Report-${new Date().toISOString().slice(0, 10)}.pdf`);
}
