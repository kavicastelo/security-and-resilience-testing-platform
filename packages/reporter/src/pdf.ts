import { ReportInput } from '@security-lab/contracts';
import { calculatePostureScore } from '@security-lab/scoring';
import { assessCompliance } from './compliance/index.js';

/**
 * Escapes characters for PDF literal strings enclosed in parentheses.
 */
function escapePdfText(text: string): string {
  if (!text) return '';
  // Sanitize unicode bullets and dashes to standard ASCII
  const sanitized = text
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\u2022/g, '*')
    .replace(/[^\x20-\x7E\n\r\t]/g, '');

  return sanitized
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

/**
 * Lightweight, zero-dependency PDF 1.4 Vector Document Generator.
 * Produces compliant, multi-page executive security assessment reports.
 */
export class PdfDocumentBuilder {
  private objects: string[] = [];
  private pageObjectIds: number[] = [];
  private currentPageCommands: string[] = [];
  private currentY = 720;
  private readonly pageWidth = 612; // US Letter width
  private readonly pageHeight = 792; // US Letter height
  private readonly margin = 40;

  constructor() {
    // Reserve object 1 for Catalog and object 2 for Pages root
    this.objects.push(''); // placeholder for obj 1
    this.objects.push(''); // placeholder for obj 2
  }

  startPage(): void {
    if (this.currentPageCommands.length > 0 || this.pageObjectIds.length === 0) {
      this.flushCurrentPage();
    }
    this.currentY = this.pageHeight - this.margin;
  }

  private flushCurrentPage(): void {
    if (this.currentPageCommands.length === 0 && this.pageObjectIds.length > 0) return;

    // 1. Create content stream object
    const streamContent = this.currentPageCommands.join('\n');
    const streamObjId = this.objects.length + 1;
    const streamObj = `${streamObjId} 0 obj\n<< /Length ${Buffer.byteLength(streamContent, 'utf-8')} >>\nstream\n${streamContent}\nendstream\nendobj`;
    this.objects.push(streamObj);

    // 2. Create Page object referencing stream
    const pageObjId = this.objects.length + 1;
    const pageObj = `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${this.pageWidth} ${this.pageHeight}] /Contents ${streamObjId} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>\nendobj`;
    this.objects.push(pageObj);

    this.pageObjectIds.push(pageObjId);
    this.currentPageCommands = [];
  }

  checkPageBreak(neededHeight: number): void {
    if (this.currentY - neededHeight < this.margin + 30) {
      this.startPage();
    }
  }

  drawRect(x: number, y: number, w: number, h: number, r: number, g: number, b: number, fill = true): void {
    this.currentPageCommands.push('q');
    this.currentPageCommands.push(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} ${fill ? 'rg' : 'RG'}`);
    this.currentPageCommands.push(`${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re ${fill ? 'f' : 's'}`);
    this.currentPageCommands.push('Q');
  }

  drawText(
    text: string,
    x: number,
    y: number,
    fontSize = 10,
    isBold = false,
    color = { r: 0.1, g: 0.1, b: 0.1 },
    font = 'F1',
  ): void {
    const selectedFont = isBold ? 'F2' : font;
    const safeText = escapePdfText(text);
    this.currentPageCommands.push('BT');
    this.currentPageCommands.push(`/${selectedFont} ${fontSize} Tf`);
    this.currentPageCommands.push(`${color.r.toFixed(3)} ${color.g.toFixed(3)} ${color.b.toFixed(3)} rg`);
    this.currentPageCommands.push(`${x.toFixed(2)} ${y.toFixed(2)} Td`);
    this.currentPageCommands.push(`(${safeText}) Tj`);
    this.currentPageCommands.push('ET');
  }

  drawWrappedText(
    text: string,
    x: number,
    startY: number,
    maxWidth: number,
    fontSize = 9,
    lineHeight = 12,
    color = { r: 0.2, g: 0.2, b: 0.2 },
  ): number {
    const words = text.split(/\s+/);
    let line = '';
    let y = startY;
    const approxCharsPerLine = Math.floor(maxWidth / (fontSize * 0.52));

    for (const word of words) {
      const testLine = line.length === 0 ? word : `${line} ${word}`;
      if (testLine.length > approxCharsPerLine) {
        this.checkPageBreak(lineHeight);
        this.drawText(line, x, y, fontSize, false, color);
        y -= lineHeight;
        line = word;
      } else {
        line = testLine;
      }
    }

    if (line.length > 0) {
      this.drawText(line, x, y, fontSize, false, color);
      y -= lineHeight;
    }

    return y;
  }

  build(): Buffer {
    this.flushCurrentPage();

    // Font 3: Helvetica
    const f1Obj = '3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj';
    // Font 4: Helvetica-Bold
    const f2Obj = '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj';
    // Font 5: Courier
    const f3Obj = '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj';

    // Place font objects
    this.objects.splice(2, 0, f1Obj, f2Obj, f3Obj);

    // Object 1: Catalog
    const catalogObj = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj';
    // Object 2: Pages root
    const kidsStr = this.pageObjectIds.map((id) => `${id} 0 R`).join(' ');
    const pagesObj = `2 0 obj\n<< /Type /Pages /Kids [${kidsStr}] /Count ${this.pageObjectIds.length} >>\nendobj`;

    this.objects[0] = catalogObj;
    this.objects[1] = pagesObj;

    // Assemble PDF buffer with xref table
    let body = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
    const offsets: number[] = [0]; // 0000000000 65535 f

    for (const obj of this.objects) {
      offsets.push(Buffer.byteLength(body, 'utf-8'));
      body += `${obj}\n`;
    }

    const xrefOffset = Buffer.byteLength(body, 'utf-8');
    let xref = `xref\n0 ${this.objects.length + 1}\n0000000000 65535 f \n`;

    for (let i = 1; i <= this.objects.length; i++) {
      const offset = offsets[i]!;
      const padded = String(offset).padStart(10, '0');
      xref += `${padded} 00000 n \n`;
    }

    const trailer = `trailer\n<< /Size ${this.objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

    return Buffer.from(body + xref + trailer, 'utf-8');
  }
}

/**
 * Generates an executive-ready, branded PDF assessment report.
 */
export function generateExecutivePdfReport(input: ReportInput): Buffer {
  const { testRun, target, findings, releaseGate } = input;
  const posture = input.posture || calculatePostureScore(findings);
  const targetUrl = target?.baseUrl || 'N/A';
  const targetName = target?.name || testRun.targetId;

  const compliance = assessCompliance(findings, testRun.id, targetUrl);
  const counts = compliance.countsBySeverity;

  const pdf = new PdfDocumentBuilder();

  // =========================================================================
  // PAGE 1: Executive Cover Page & Scorecard
  // =========================================================================
  pdf.startPage();

  // Top Branded Header Banner (Deep Navy #0f172a)
  pdf.drawRect(0, 680, 612, 112, 0.059, 0.09, 0.165, true);

  // Title & Subtitle
  pdf.drawText('SECURITY LAB & COMPLIANCE ASSESSMENT', 40, 745, 18, true, { r: 1, g: 1, b: 1 });
  pdf.drawText('EXECUTIVE PENETRATION TEST & AUDIT REPORT', 40, 725, 12, false, { r: 0.58, g: 0.64, b: 0.72 });
  pdf.drawText(`Confidential Assessment &bull; Target: ${targetName}`, 40, 700, 10, false, { r: 0.75, g: 0.82, b: 0.9 });

  // Metadata Card
  pdf.drawRect(40, 560, 532, 100, 0.96, 0.97, 0.98, true);
  pdf.drawRect(40, 560, 532, 100, 0.85, 0.88, 0.91, false);

  pdf.drawText('TARGET & EXECUTION PARAMETERS', 55, 640, 10, true, { r: 0.28, g: 0.35, b: 0.44 });
  pdf.drawText(`Application Base URL: ${targetUrl}`, 55, 620, 9, false);
  pdf.drawText(`Test Run Identifier:  ${testRun.id}`, 55, 605, 9, false, { r: 0.1, g: 0.1, b: 0.1 }, 'F3');
  pdf.drawText(`Execution Timestamp:  ${new Date().toUTCString()}`, 55, 590, 9, false);
  pdf.drawText(`Audit Scope:          Continuous Dynamic & Protocol Hardening Audit`, 55, 575, 9, false);

  // Security Posture Score & Release Gate Cards
  pdf.drawRect(40, 430, 256, 110, 0.96, 0.97, 0.98, true);
  pdf.drawRect(40, 430, 256, 110, 0.85, 0.88, 0.91, false);

  pdf.drawText('OVERALL SECURITY POSTURE', 55, 520, 10, true, { r: 0.28, g: 0.35, b: 0.44 });
  const riskLabel = ((posture as any).riskLevel || (posture.score >= 80 ? 'LOW' : posture.score >= 50 ? 'MEDIUM' : 'HIGH')).toUpperCase();
  pdf.drawText(`Grade: ${posture.grade}  |  Risk Level: ${riskLabel}`, 55, 450, 10, true, { r: 0.2, g: 0.2, b: 0.2 });

  // Release Gate Decision Card
  const gateDecision = releaseGate?.decision || (posture.score >= 80 ? 'passed' : 'failed');
  const gateColor =
    gateDecision === 'passed'
      ? { r: 0.06, g: 0.73, b: 0.51 }
      : gateDecision === 'warning'
        ? { r: 0.96, g: 0.62, b: 0.04 }
        : { r: 0.94, g: 0.27, b: 0.27 };

  pdf.drawRect(316, 430, 256, 110, 0.96, 0.97, 0.98, true);
  pdf.drawRect(316, 430, 256, 110, 0.85, 0.88, 0.91, false);

  pdf.drawText('CI/CD RELEASE GATE STATUS', 331, 520, 10, true, { r: 0.28, g: 0.35, b: 0.44 });
  pdf.drawText(gateDecision.toUpperCase(), 331, 480, 26, true, gateColor);
  pdf.drawText(
    gateDecision === 'passed'
      ? 'Security Gate Cleared for Production'
      : 'Release Blocked by Security Policy',
    331,
    450,
    9,
    false,
    { r: 0.3, g: 0.3, b: 0.3 },
  );

  // Severity Distribution Table
  pdf.drawText('VULNERABILITY SEVERITY BREAKDOWN', 40, 400, 11, true, { r: 0.1, g: 0.15, b: 0.25 });
  pdf.drawRect(40, 290, 532, 95, 0.98, 0.98, 0.99, true);
  pdf.drawRect(40, 290, 532, 95, 0.85, 0.88, 0.91, false);

  // Table Header
  pdf.drawRect(40, 360, 532, 25, 0.91, 0.93, 0.96, true);
  pdf.drawText('Severity Level', 55, 368, 9, true);
  pdf.drawText('Count', 200, 368, 9, true);
  pdf.drawText('Standard SLA', 280, 368, 9, true);
  pdf.drawText('Release Impact', 430, 368, 9, true);

  // Rows
  const sevRows = [
    { label: 'CRITICAL', count: counts.critical, sla: '24 Hours', impact: 'Blocks Release', c: { r: 0.94, g: 0.27, b: 0.27 } },
    { label: 'HIGH', count: counts.high, sla: '7 Days', impact: 'Blocks Release', c: { r: 0.98, g: 0.45, b: 0.09 } },
    { label: 'MEDIUM', count: counts.medium, sla: '30 Days', impact: 'Warning / Review', c: { r: 0.96, g: 0.62, b: 0.04 } },
    { label: 'LOW', count: counts.low, sla: '90 Days', impact: 'Advisory', c: { r: 0.23, g: 0.51, b: 0.96 } },
  ];

  let rowY = 345;
  for (const sr of sevRows) {
    pdf.drawText(sr.label, 55, rowY, 9, true, sr.c);
    pdf.drawText(String(sr.count), 200, rowY, 9, true);
    pdf.drawText(sr.sla, 280, rowY, 9, false);
    pdf.drawText(sr.impact, 430, rowY, 9, false);
    rowY -= 17;
  }

  // Regulatory Compliance Overview
  pdf.drawText('REGULATORY COMPLIANCE AT A GLANCE', 40, 260, 11, true, { r: 0.1, g: 0.15, b: 0.25 });

  const compFrameworks = [
    { name: 'OWASP Top 10 (2021)', pct: compliance.owaspTop10.compliancePercentage, status: compliance.owaspTop10.overallStatus },
    { name: 'OWASP ASVS 4.0', pct: compliance.asvs.compliancePercentage, status: compliance.asvs.overallStatus },
    { name: 'PCI-DSS v4.0 (Req 6)', pct: compliance.pciDss.compliancePercentage, status: compliance.pciDss.overallStatus },
  ];

  let cY = 230;
  for (const cf of compFrameworks) {
    pdf.drawText(cf.name, 40, cY, 9, true);
    pdf.drawText(`${cf.pct}% (${cf.status})`, 250, cY, 9, true, cf.pct >= 80 ? { r: 0.06, g: 0.73, b: 0.51 } : { r: 0.94, g: 0.27, b: 0.27 });

    // Progress Bar
    pdf.drawRect(350, cY - 2, 222, 10, 0.88, 0.9, 0.92, true);
    const fillWidth = (cf.pct / 100) * 222;
    if (fillWidth > 0) {
      pdf.drawRect(350, cY - 2, fillWidth, 10, cf.pct >= 80 ? 0.06 : 0.94, cf.pct >= 80 ? 0.73 : 0.27, cf.pct >= 80 ? 0.51 : 0.27, true);
    }
    cY -= 26;
  }

  // Footer
  pdf.drawText('Generated by Security & Resilience Testing Platform &bull; Page 1', 40, 30, 8, false, { r: 0.5, g: 0.5, b: 0.5 });

  // =========================================================================
  // PAGE 2: Detailed Vulnerability Findings Dossier
  // =========================================================================
  pdf.startPage();
  pdf.drawText('DETAILED VULNERABILITY FINDINGS DOSSIER', 40, 745, 14, true, { r: 0.06, g: 0.09, b: 0.17 });
  pdf.drawText(`Listing ${findings.length} findings categorized by severity and compliance requirement`, 40, 730, 9, false, { r: 0.4, g: 0.45, b: 0.5 });
  pdf.drawRect(40, 720, 532, 1, 0.85, 0.88, 0.91, true);

  let currentY = 700;

  if (compliance.findings.length === 0) {
    pdf.drawText('No security findings identified. Target endpoint passed all automated tests.', 40, currentY, 11, false);
  } else {
    for (const f of compliance.findings) {
      pdf.checkPageBreak(120);

      const sevColor =
        f.severity === 'critical'
          ? { r: 0.94, g: 0.27, b: 0.27 }
          : f.severity === 'high'
            ? { r: 0.98, g: 0.45, b: 0.09 }
            : f.severity === 'medium'
              ? { r: 0.96, g: 0.62, b: 0.04 }
              : { r: 0.23, g: 0.51, b: 0.96 };

      // Finding Header Box
      pdf.drawRect(40, currentY - 18, 532, 22, 0.95, 0.96, 0.98, true);
      pdf.drawText(`[${f.severity.toUpperCase()}] ${f.title}`, 45, currentY - 12, 10, true, sevColor);
      pdf.drawText(`Status: ${f.status.toUpperCase()}`, 480, currentY - 12, 9, false, { r: 0.3, g: 0.3, b: 0.3 });
      currentY -= 28;

      // Compliance Mapping Line
      pdf.drawText(
        `OWASP: ${f.compliance.owaspTop10.id} (${f.compliance.owaspTop10.name}) | ASVS: ${f.compliance.asvs.requirementId} | PCI: ${f.compliance.pciDss.requirementId} | ${f.compliance.cwe}`,
        45,
        currentY,
        8,
        true,
        { r: 0.23, g: 0.45, b: 0.78 },
      );
      currentY -= 14;

      // Description
      currentY = pdf.drawWrappedText(f.description, 45, currentY, 520, 8.5, 11);
      currentY -= 4;

      // Remediation Guidance
      if (f.recommendation) {
        pdf.drawRect(45, currentY - 16, 520, 18, 0.92, 0.98, 0.94, true);
        pdf.drawText(`Fix: ${f.recommendation}`, 50, currentY - 11, 8, false, { r: 0.05, g: 0.45, b: 0.25 });
        currentY -= 24;
      }

      currentY -= 10;
    }
  }

  // Footer Page 2
  pdf.drawText('Generated by Security & Resilience Testing Platform &bull; Page 2', 40, 30, 8, false, { r: 0.5, g: 0.5, b: 0.5 });

  return pdf.build();
}
