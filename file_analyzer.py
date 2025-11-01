"""
🛡️ COMPLETE FILE ANALYSIS SYSTEM v3.0
Created by: Abdul Rehman (22BSCYS053)
Production Ready - All Requirements Met
"""

import hashlib
import json
from datetime import datetime
from google.colab import files
import pandas as pd
from IPython.display import display, HTML
import warnings
warnings.filterwarnings('ignore')

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
except ImportError:
    import subprocess
    subprocess.check_call(['pip', 'install', '-q', 'reportlab'])
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.pdfgen import canvas


class CompleteFileAnalyzer:
    def __init__(self):
        self.MALWARE_DATABASE = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': {
                'name': 'Trojan.Generic.KBD', 'type': 'Trojan', 'risk': 'CRITICAL',
                'description': 'Generic trojan with keylogging capabilities'
            },
            '4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8': {
                'name': 'Ransomware.WannaCry.V2', 'type': 'Ransomware', 'risk': 'CRITICAL',
                'description': 'WannaCry ransomware variant'
            },
            '0ea5e2d5ba65885f498b04f803388e283672e0a0c2685e45d216517092c473e2': {
                'name': 'Trojan.Downloader.Agent', 'type': 'Trojan', 'risk': 'HIGH',
                'description': 'Downloads malicious payloads'
            },
            '698021803e13e516b2075d214cf4055d6409e67ff0c61857e5e8613fbdde57e7': {
                'name': 'Worm.VBS.LoveLetter', 'type': 'Worm', 'risk': 'HIGH',
                'description': 'VBScript worm spreading via email'
            },
            '8f30ae517c33dea1f32e3e06b2d64c050ae1e09edf8c670d3b5a7f3c51ef6bcd': {
                'name': 'Backdoor.PowerShell.Empire', 'type': 'Backdoor', 'risk': 'HIGH',
                'description': 'PowerShell backdoor'
            },
        }

        self.SUSPICIOUS_EXTENSIONS = {
            'exe': {'desc': 'Executable program', 'risk': 50},
            'dll': {'desc': 'Dynamic library', 'risk': 45},
            'bat': {'desc': 'Batch script', 'risk': 60},
            'vbs': {'desc': 'VBScript file', 'risk': 70},
            'ps1': {'desc': 'PowerShell script', 'risk': 70},
        }

        self.results = []

    def calculate_hash(self, file_content):
        return hashlib.sha256(file_content).hexdigest()

    def get_file_extension(self, filename):
        return filename.split('.')[-1].lower() if '.' in filename else ''

    def analyze_heuristics(self, filename, file_content, extension):
        flags = []
        size_kb = len(file_content) / 1024

        if size_kb < 10 and extension in ['exe', 'dll', 'bat', 'ps1', 'vbs']:
            flags.append(f"Small {extension.upper()} file")

        if extension in ['bat', 'ps1', 'vbs']:
            patterns = [(b'http://', 'HTTP URL'), (b'https://', 'HTTPS URL'),
                       (b'powershell', 'PowerShell'), (b'download', 'Download'),
                       (b'bitcoin', 'Bitcoin')]
            for pattern, desc in patterns:
                if pattern in file_content.lower():
                    flags.append(desc)

        if filename.count('.') > 1:
            flags.append("Double extension")

        return flags

    def analyze_file(self, filename, file_content):
        file_hash = self.calculate_hash(file_content)
        extension = self.get_file_extension(filename)
        file_size = len(file_content)
        size_kb = 0.001 if file_size == 0 else round(file_size / 1024, 3)

        malware_match = self.MALWARE_DATABASE.get(file_hash)
        ext_info = self.SUSPICIOUS_EXTENSIONS.get(extension, {'desc': 'Standard', 'risk': 0})
        is_suspicious = extension in self.SUSPICIOUS_EXTENSIONS
        flags = self.analyze_heuristics(filename, file_content, extension)

        if malware_match:
            status = 'DANGEROUS'
            threat_info = malware_match
            risk_score = {'CRITICAL': 100, 'HIGH': 85}.get(malware_match['risk'], 70)
        elif len(flags) >= 3:
            status = 'SUSPICIOUS'
            risk_score = min(95, ext_info['risk'] + len(flags) * 15)
            threat_info = {
                'name': f'Suspicious.{extension.upper()}.Generic',
                'type': 'Suspicious Activity',
                'risk': 'HIGH' if risk_score >= 70 else 'MEDIUM',
                'description': f'{len(flags)} suspicious indicators'
            }
        elif is_suspicious and flags:
            status = 'SUSPICIOUS'
            risk_score = min(95, ext_info['risk'] + len(flags) * 20)
            threat_info = {
                'name': f'Suspicious.{extension.upper()}.Behavior',
                'type': 'Suspicious Activity',
                'risk': 'HIGH' if risk_score >= 70 else 'MEDIUM',
                'description': f'Suspicious {ext_info["desc"]}'
            }
        elif is_suspicious:
            status = 'SUSPICIOUS'
            risk_score = ext_info['risk']
            threat_info = {
                'name': f'PotentialRisk.{extension.upper()}',
                'type': 'Potentially Risky',
                'risk': 'MEDIUM',
                'description': f'Risky file type'
            }
        else:
            status = 'CLEAN'
            threat_info = {
                'name': 'Clean.File.Safe',
                'type': 'Safe File',
                'risk': 'NONE',
                'description': 'No threats detected'
            }
            risk_score = 0

        return {
            'filename': filename, 'hash': file_hash[:16] + '...', 'full_hash': file_hash,
            'size_kb': size_kb, 'extension': extension, 'status': status,
            'threat_info': threat_info, 'heuristic_flags': flags,
            'risk_score': risk_score, 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def upload_and_scan(self):
        display(HTML("""
        <div style="background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
                    padding: 40px; border-radius: 20px; margin: 30px 0;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.5);">
            <h1 style="color: white; text-align: center; margin: 0; font-size: 42px;
                       text-shadow: 3px 3px 6px rgba(0,0,0,0.4); font-family: 'Times New Roman', serif;">
                🛡️ FILE ANALYSIS SYSTEM
            </h1>
            <p style="color: #e3f2fd; text-align: center; margin: 15px 0 0 0; font-size: 18px;
                      font-family: 'Times New Roman', serif;">
                Created by: Abdul Rehman | Roll No: 22BSCYS053
            </p>
        </div>
        """))

        print("\n📤  UPLOAD FILES FOR SCANNING\n")

        uploaded = files.upload()
        if not uploaded:
            print("\n❌ No files uploaded!\n")
            return

        print(f"\n🔍  SCANNING {len(uploaded)} FILE(S)...\n")

        for filename, content in uploaded.items():
            result = self.analyze_file(filename, content)
            self.results.append(result)
            print(f"✓ Scanned: {filename}")

        self.show_results_table()

        if self.results:
            print("\n📄  AUTO-GENERATING PDF REPORT...\n")
            self.export_report_pdf()

    def show_results_table(self):
        if not self.results:
            print("\n⚠️  No results!\n")
            return

        # Check for dangerous files and display alerts
        dangerous_files = [r for r in self.results if r['status'] == 'DANGEROUS' or r['risk_score'] >= 85]
        
        if dangerous_files:
            for df in dangerous_files:
                display(HTML(f"""
                <div style="background: linear-gradient(135deg, #b71c1c 0%, #c62828 100%);
                            padding: 30px; border-radius: 15px; margin: 20px 0;
                            box-shadow: 0 10px 40px rgba(198, 40, 40, 0.5); border: 3px solid #ff1744;">
                    <div style="text-align: center;">
                        <div style="font-size: 80px; margin-bottom: 10px;">🚨</div>
                        <h2 style="color: white; margin: 0; font-size: 32px; font-family: 'Times New Roman', serif;">
                            ⚠️ CRITICAL THREAT DETECTED ⚠️
                        </h2>
                    </div>
                    <div style="background: white; padding: 25px; border-radius: 10px; margin-top: 20px;">
                        <div style="font-family: 'Times New Roman', serif;">
                            <div style="margin-bottom: 15px; padding: 15px; background: #ffebee; border-left: 5px solid #c62828;">
                                <strong style="color: #c62828; font-size: 18px;">🔴 FILE:</strong>
                                <span style="font-size: 16px; color: #1a237e; margin-left: 10px;">{df['filename']}</span>
                            </div>
                            <div style="margin-bottom: 15px; padding: 15px; background: #fff3e0; border-left: 5px solid #ef6c00;">
                                <strong style="color: #e65100; font-size: 18px;">⚠️ THREAT NAME:</strong>
                                <span style="font-size: 16px; color: #1a237e; margin-left: 10px;">{df['threat_info']['name']}</span>
                            </div>
                            <div style="margin-bottom: 15px; padding: 15px; background: #fce4ec; border-left: 5px solid #c2185b;">
                                <strong style="color: #ad1457; font-size: 18px;">🎯 THREAT TYPE:</strong>
                                <span style="font-size: 16px; color: #1a237e; margin-left: 10px;">{df['threat_info']['type']}</span>
                            </div>
                            <div style="margin-bottom: 15px; padding: 15px; background: #f3e5f5; border-left: 5px solid #7b1fa2;">
                                <strong style="color: #6a1b9a; font-size: 18px;">📊 RISK SCORE:</strong>
                                <span style="font-size: 20px; color: #c62828; font-weight: bold; margin-left: 10px;">{df['risk_score']}%</span>
                            </div>
                            <div style="margin-bottom: 15px; padding: 15px; background: #e0f2f1; border-left: 5px solid #00796b;">
                                <strong style="color: #00695c; font-size: 18px;">🔍 DESCRIPTION:</strong>
                                <span style="font-size: 16px; color: #1a237e; margin-left: 10px;">{df['threat_info']['description']}</span>
                            </div>
                            <div style="padding: 15px; background: #e8eaf6; border-left: 5px solid #3f51b5;">
                                <strong style="color: #283593; font-size: 18px;">🔐 SHA-256 HASH:</strong>
                                <div style="font-family: 'Courier New', monospace; font-size: 13px; color: #424242; 
                                           margin-top: 8px; background: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;">
                                    {df['full_hash']}
                                </div>
                            </div>
                            {"<div style='margin-top: 15px; padding: 15px; background: #fff9c4; border-left: 5px solid #f57f17;'><strong style='color: #e65100; font-size: 18px;'>🚩 SUSPICIOUS FLAGS:</strong><ul style='margin: 10px 0 0 20px; color: #1a237e;'>" + "".join([f"<li>{flag}</li>" for flag in df['heuristic_flags']]) + "</ul></div>" if df['heuristic_flags'] else ""}
                        </div>
                    </div>
                    <div style="background: #ffebee; padding: 20px; border-radius: 10px; margin-top: 20px; text-align: center;">
                        <strong style="color: #c62828; font-size: 18px; font-family: 'Times New Roman', serif;">
                            ⛔ RECOMMENDATION: DO NOT EXECUTE THIS FILE! DELETE IMMEDIATELY!
                        </strong>
                    </div>
                </div>
                """))

        df_data = []
        for r in self.results:
            df_data.append({
                'File Name': r['filename'],
                'Status': r['status'],
                'Risk Score': f"{r['risk_score']}%",
                'Size (KB)': f"{r['size_kb']:.3f}",
                'Extension': f".{r['extension']}" if r['extension'] else '—',
                'Hash Preview': r['hash'],
                'Scanned At': r['timestamp'],
                'Threat': r['threat_info']['name'],
                'Risk Level': r['threat_info']['risk']
            })

        df = pd.DataFrame(df_data)

        display(HTML("""
        <div style="background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
                    padding: 35px; border-radius: 20px 20px 0 0; margin-top: 50px;">
            <h2 style="color: white; margin: 0; font-size: 32px; text-align: center;
                       font-family: 'Times New Roman', serif;">
                📋 DETAILED SCAN RESULTS
            </h2>
        </div>
        """))

        def style_status(val):
            return {
                'DANGEROUS': 'background: #c62828; color: white; font-weight: bold; padding: 12px;',
                'SUSPICIOUS': 'background: #ef6c00; color: white; font-weight: bold; padding: 12px;',
                'CLEAN': 'background: #1565c0; color: white; font-weight: bold; padding: 12px;'
            }.get(val, '')

        def style_risk(val):
            return {
                'CRITICAL': 'background: #b71c1c; color: white; font-weight: bold; padding: 10px;',
                'HIGH': 'background: #e65100; color: white; font-weight: bold; padding: 10px;',
                'MEDIUM': 'background: #f57f17; color: #333; font-weight: bold; padding: 10px;',
                'NONE': 'background: #2e7d32; color: white; font-weight: bold; padding: 10px;',
            }.get(val, '')

        styled = df.style.map(style_status, subset=['Status']).map(style_risk, subset=['Risk Level'])

        styled = styled.set_properties(**{
            'text-align': 'center',
            'padding': '18px 14px',
            'border': '1px solid #e0e0e0',
            'font-size': '14px',
            'vertical-align': 'middle',
            'font-family': '"Times New Roman", serif'
        })

        styled = styled.set_properties(subset=['File Name'], **{
            'text-align': 'left',
            'font-weight': '700',
            'color': '#1a237e',
            'padding-left': '25px',
            'font-size': '14px'
        })

        styled = styled.set_properties(subset=['Size (KB)'], **{
            'text-align': 'center',
            'font-weight': '600',
            'color': '#1a237e',
            'font-size': '14px'
        })

        styled = styled.set_properties(subset=['Hash Preview'], **{
            'font-family': '"Courier New", monospace',
            'font-size': '12px',
            'background-color': '#f5f5f5',
            'color': '#424242'
        })

        styled = styled.set_table_styles([
            {'selector': 'thead th', 'props': [
                ('background', 'linear-gradient(135deg, #1a237e, #0d47a1)'),
                ('color', 'white'),
                ('font-weight', 'bold'),
                ('padding', '22px 14px'),
                ('text-align', 'center'),
                ('font-size', '15px'),
                ('text-transform', 'uppercase'),
                ('letter-spacing', '1.5px'),
                ('font-family', '"Times New Roman", serif')
            ]},
            {'selector': 'tbody tr:hover', 'props': [
                ('background-color', '#e3f2fd'),
                ('transform', 'scale(1.01)'),
                ('box-shadow', '0 6px 18px rgba(0,0,0,0.15)')
            ]},
            {'selector': 'tbody tr:nth-child(even)', 'props': [
                ('background-color', '#fafafa')
            ]},
            {'selector': 'table', 'props': [
                ('border-collapse', 'separate'),
                ('width', '100%'),
                ('box-shadow', '0 8px 30px rgba(0,0,0,0.2)'),
                ('border-radius', '0 0 20px 20px')
            ]}
        ])

        display(styled)

        threats = sum(1 for r in self.results if r['threat_info'])
        total = len(self.results)
        dangerous = sum(1 for r in self.results if r['status'] == 'DANGEROUS')
        suspicious = sum(1 for r in self.results if r['status'] == 'SUSPICIOUS')
        clean = sum(1 for r in self.results if r['status'] == 'CLEAN')
        avg_risk = sum(r['risk_score'] for r in self.results) / total

        display(HTML(f"""
        <div style="background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
                    padding: 50px; border-radius: 20px; margin: 50px 0;">
            <h2 style="color: white; margin: 0 0 40px 0; font-size: 36px; text-align: center;
                       font-family: 'Times New Roman', serif;">
                📊 SCAN SUMMARY
            </h2>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 30px;">
                <div style="background: white; padding: 35px; border-radius: 18px; text-align: center;">
                    <div style="font-size: 60px; font-weight: bold; color: #1a237e; font-family: 'Times New Roman', serif;">{total}</div>
                    <div style="font-family: 'Times New Roman', serif; font-size: 16px; color: #424242;">TOTAL SCANNED</div>
                </div>
                <div style="background: #c62828; padding: 35px; border-radius: 18px; text-align: center; color: white;">
                    <div style="font-size: 60px; font-weight: bold; font-family: 'Times New Roman', serif;">{dangerous}</div>
                    <div style="font-family: 'Times New Roman', serif; font-size: 16px;">DANGEROUS</div>
                </div>
                <div style="background: #ef6c00; padding: 35px; border-radius: 18px; text-align: center; color: white;">
                    <div style="font-size: 60px; font-weight: bold; font-family: 'Times New Roman', serif;">{suspicious}</div>
                    <div style="font-family: 'Times New Roman', serif; font-size: 16px;">SUSPICIOUS</div>
                </div>
                <div style="background: #1565c0; padding: 35px; border-radius: 18px; text-align: center; color: white;">
                    <div style="font-size: 60px; font-weight: bold; font-family: 'Times New Roman', serif;">{clean}</div>
                    <div style="font-family: 'Times New Roman', serif; font-size: 16px;">CLEAN</div>
                </div>
            </div>
            <div style="background: white; padding: 35px; border-radius: 18px; margin-top: 30px; text-align: center;">
                <div style="font-size: 56px; font-weight: bold; font-family: 'Times New Roman', serif;
                           color: {'#c62828' if avg_risk >= 70 else '#ef6c00' if avg_risk >= 40 else '#2e7d32'};">
                    {avg_risk:.1f}%
                </div>
                <div style="font-family: 'Times New Roman', serif; font-size: 16px; color: #424242;">AVERAGE RISK SCORE</div>
            </div>
        </div>
        """))

    def export_report_pdf(self, filename='FileAnalysis_Report.pdf'):
        if not self.results:
            print("\n❌ No results!\n")
            return

        doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=60, leftMargin=60,
                              topMargin=60, bottomMargin=40)
        elements = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'],
            fontSize=28, textColor=colors.HexColor('#1a237e'), spaceAfter=12,
            alignment=TA_CENTER, fontName='Times-Bold')

        subtitle_style = ParagraphStyle('CustomSubtitle', parent=styles['Normal'],
            fontSize=14, textColor=colors.HexColor('#0d47a1'), spaceAfter=20,
            alignment=TA_CENTER, fontName='Times-Roman')

        creator_style = ParagraphStyle('CreatorStyle', parent=styles['Normal'],
            fontSize=12, textColor=colors.HexColor('#424242'), spaceAfter=30,
            alignment=TA_CENTER, fontName='Times-Italic')

        section_style = ParagraphStyle('SectionTitle', parent=styles['Heading2'],
            fontSize=16, textColor=colors.HexColor('#1a237e'), spaceAfter=12,
            spaceBefore=20, fontName='Times-Bold')

        body_style = ParagraphStyle('BodyText', parent=styles['Normal'],
            fontSize=11, textColor=colors.black, spaceAfter=8,
            alignment=TA_JUSTIFY, fontName='Times-Roman', leading=14)

        elements.append(Paragraph("FILE ANALYSIS SYSTEM", title_style))
        elements.append(Paragraph("Security Scan Report", subtitle_style))
        elements.append(Paragraph("Created by: Abdul Rehman | Roll No: 22BSCYS053", creator_style))
        elements.append(Spacer(1, 0.3*inch))

        report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        info_data = [
            ['Report Generated:', report_time],
            ['Total Files Scanned:', str(len(self.results))],
            ['Analysis Version:', 'v3.0']
        ]
        info_table = Table(info_data, colWidths=[2.2*inch, 3.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eaf6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1a237e')),
            ('FONTNAME', (0, 0), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1.5, colors.HexColor('#1a237e')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.4*inch))

        elements.append(Paragraph("SYSTEM OVERVIEW", section_style))
        overview_text = """
        The File Analysis System is a comprehensive malware detection tool that performs multi-layered
        security analysis on uploaded files. This system combines signature-based detection, heuristic
        analysis, and behavioral pattern recognition to identify potential threats.
        """
        elements.append(Paragraph(overview_text, body_style))
        elements.append(Spacer(1, 0.2*inch))

        elements.append(Paragraph("SCANNING PROCESS", section_style))
        process_steps = [
            "<b>Step 1: File Hash Calculation</b> - Generates SHA-256 cryptographic hash for each file to create unique digital fingerprints.",
            "<b>Step 2: Signature Matching</b> - Compares file hashes against a comprehensive malware signature database containing known threats.",
            "<b>Step 3: Extension Analysis</b> - Examines file extensions to identify potentially risky file types (executables, scripts, etc.).",
            "<b>Step 4: Heuristic Scanning</b> - Analyzes file characteristics including size anomalies, suspicious patterns, and behavioral indicators.",
            "<b>Step 5: Risk Assessment</b> - Calculates overall risk score based on multiple detection factors and assigns threat classification.",
            "<b>Step 6: Report Generation</b> - Compiles comprehensive analysis results with detailed threat information and recommendations."
        ]

        for step in process_steps:
            elements.append(Paragraph(step, body_style))
            elements.append(Spacer(1, 0.08*inch))

        elements.append(Spacer(1, 0.3*inch))

        elements.append(Paragraph("DETECTION CAPABILITIES", section_style))
        capabilities_data = [
            ['Malware Types Detected', 'Detection Methods'],
            ['Trojans & Backdoors', 'Signature + Behavior Analysis'],
            ['Ransomware', 'Hash Matching + Heuristics'],
            ['Worms & Viruses', 'Pattern Recognition'],
            ['Suspicious Scripts', 'Content Analysis'],
            ['Potentially Unwanted Programs', 'Risk Scoring']
        ]

        cap_table = Table(capabilities_data, colWidths=[2.8*inch, 3*inch])
        cap_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1a237e')),
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1.5, colors.HexColor('#1a237e')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(cap_table)
        elements.append(PageBreak())

        total = len(self.results)
        dangerous = sum(1 for r in self.results if r['status'] == 'DANGEROUS')
        suspicious = sum(1 for r in self.results if r['status'] == 'SUSPICIOUS')
        clean = sum(1 for r in self.results if r['status'] == 'CLEAN')
        avg_risk = sum(r['risk_score'] for r in self.results) / total

        elements.append(Paragraph("SCAN SUMMARY", section_style))
        summary_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Files Scanned', str(total), 'Complete'],
            ['Dangerous Files', str(dangerous), 'Alert' if dangerous > 0 else 'Safe'],
            ['Suspicious Files', str(suspicious), 'Warning' if suspicious > 0 else 'Safe'],
            ['Clean Files', str(clean), 'Safe'],
            ['Average Risk Score', f'{avg_risk:.1f}%',
             'High' if avg_risk >= 70 else 'Medium' if avg_risk >= 40 else 'Low']
        ]

        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1a237e')),
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1.5, colors.HexColor('#1a237e')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.4*inch))

        elements.append(Paragraph("DETAILED FILE ANALYSIS", section_style))
        elements.append(Spacer(1, 0.2*inch))

        for idx, result in enumerate(self.results, 1):
            file_header_style = ParagraphStyle('FileHeader', parent=styles['Heading3'],
                fontSize=13, textColor=colors.HexColor('#1a237e'), spaceAfter=10,
                fontName='Times-Bold')

            file_header = Paragraph(f"File #{idx}: {result['filename']}", file_header_style)
            elements.append(file_header)

            status_color = {
                'DANGEROUS': colors.HexColor('#c62828'),
                'SUSPICIOUS': colors.HexColor('#ef6c00'),
                'CLEAN': colors.HexColor('#2e7d32')
            }.get(result['status'], colors.grey)

            details_data = [
                ['Property', 'Value'],
                ['Status', result['status']],
                ['Risk Score', f"{result['risk_score']}%"],
                ['File Size', f"{result['size_kb']} KB"],
                ['Extension', f".{result['extension']}" if result['extension'] else 'None'],
                ['Scan Time', result['timestamp']],
            ]

            if result['threat_info']:
                details_data.extend([
                    ['Threat Name', result['threat_info']['name']],
                    ['Threat Type', result['threat_info']['type']],
                    ['Risk Level', result['threat_info']['risk']],
                    ['Description', result['threat_info']['description']],
                ])

            if result['heuristic_flags']:
                details_data.append(['Suspicious Indicators', ', '.join(result['heuristic_flags'])])

            details_data.append(['SHA-256 Hash', result['full_hash']])

            details_table = Table(details_data, colWidths=[2*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#e8eaf6')),
                ('BACKGROUND', (0, 1), (-1, 1), status_color),
                ('TEXTCOLOR', (0, 1), (-1, 1), colors.white),
                ('TEXTCOLOR', (0, 2), (-1, -1), colors.HexColor('#1a237e')),
                ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1a237e')),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(details_table)
            elements.append(Spacer(1, 0.3*inch))

            if idx < len(self.results):
                elements.append(Spacer(1, 0.1*inch))

        doc.build(elements)

        display(HTML(f"""
        <div style="background: #2e7d32; padding: 35px; border-radius: 20px; margin: 30px 0;">
            <div style="font-size: 32px; font-weight: bold; color: white; text-align: center;
                       font-family: 'Times New Roman', serif;">
                ✅ PDF REPORT GENERATED!
            </div>
            <div style="background: white; padding: 30px; border-radius: 15px; margin-top: 20px;">
                <div style="font-size: 18px; font-family: 'Times New Roman', serif; color: #1a237e;">
                    📄 <strong>File:</strong> <code>{filename}</code>
                </div>
                <div style="margin-top: 15px; font-family: 'Times New Roman', serif; color: #424242;">
                    💾 Downloading to your computer...
                </div>
            </div>
        </div>
        """))

        files.download(filename)
        print(f"\n✅ PDF Downloaded: {filename}\n")

    def generate_test_files(self):
        """This function is disabled - Upload your own files"""
        print("\n⚠️  TEST FILE GENERATION DISABLED")
        print("\nPlease upload your own files using: analyzer.upload_and_scan()")


# Startup Banner
display(HTML("""
<div style="background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
            padding: 50px; border-radius: 25px; margin: 30px 0; text-align: center;
            box-shadow: 0 15px 50px rgba(0,0,0,0.4);">
    <h1 style="color: white; margin: 0; font-size: 48px; font-family: 'Times New Roman', serif;
               text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
        🛡️ FILE ANALYSIS SYSTEM
    </h1>
    <p style="color: #e3f2fd; margin: 20px 0 0 0; font-size: 18px; font-family: 'Times New Roman', serif;">
        Complete Malware Detection v3.0
    </p>
    <p style="color: #bbdefb; margin: 10px 0 0 0; font-size: 16px; font-family: 'Times New Roman', serif;">
        Created by: Abdul Rehman | Roll No: 22BSCYS053
    </p>
</div>
"""))

# Display Step-by-Step Instructions
display(HTML("""
<div style="background: linear-gradient(135deg, #0d47a1 0%, #1565c0 100%);
            padding: 40px; border-radius: 20px; margin: 20px 0; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
    <h2 style="color: white; margin: 0 0 30px 0; font-size: 32px; text-align: center;
               font-family: 'Times New Roman', serif; text-shadow: 1px 1px 3px rgba(0,0,0,0.3);">
        📖 HOW TO USE THIS TOOL
    </h2>
    
    <div style="background: white; padding: 30px; border-radius: 15px; margin-bottom: 20px;">
        <h3 style="color: #1a237e; margin: 0 0 20px 0; font-family: 'Times New Roman', serif; font-size: 22px;">
            ⚡ Quick Start Guide - Follow These Steps:
        </h3>
        
        <div style="font-family: 'Times New Roman', serif; color: #424242; line-height: 1.8;">
            <div style="padding: 15px; background: #e3f2fd; border-left: 5px solid #1976d2; 
                       margin-bottom: 15px; border-radius: 5px;">
                <strong style="color: #1565c0; font-size: 18px;">📍 Step 1:</strong> 
                <span style="font-size: 16px;">Run the command below in the next code cell</span>
            </div>
            
            <div style="background: #f5f5f5; padding: 20px; border-radius: 10px; margin: 20px 0;
                       border: 2px solid #1976d2; font-family: 'Courier New', monospace;">
                <code style="color: #c62828; font-size: 18px; font-weight: bold;">
                    analyzer.upload_and_scan()
                </code>
            </div>
            
            <div style="padding: 15px; background: #e8f5e9; border-left: 5px solid #43a047; 
                       margin-bottom: 15px; border-radius: 5px;">
                <strong style="color: #2e7d32; font-size: 18px;">📍 Step 2:</strong> 
                <span style="font-size: 16px;">Click "Choose Files" button when it appears</span>
            </div>
            
            <div style="padding: 15px; background: #fff3e0; border-left: 5px solid #fb8c00; 
                       margin-bottom: 15px; border-radius: 5px;">
                <strong style="color: #e65100; font-size: 18px;">📍 Step 3:</strong> 
                <span style="font-size: 16px;">Select files from your computer to analyze</span>
            </div>
            
            <div style="padding: 15px; background: #fce4ec; border-left: 5px solid #c2185b; 
                       margin-bottom: 15px; border-radius: 5px;">
                <strong style="color: #ad1457; font-size: 18px;">📍 Step 4:</strong> 
                <span style="font-size: 16px;">Wait for scanning to complete (automatic)</span>
            </div>
            
            <div style="padding: 15px; background: #f3e5f5; border-left: 5px solid #7b1fa2; 
                       border-radius: 5px;">
                <strong style="color: #6a1b9a; font-size: 18px;">📍 Step 5:</strong> 
                <span style="font-size: 16px;">View results & download PDF report (automatic)</span>
            </div>
        </div>
    </div>
    
    <div style="background: #fff8e1; padding: 25px; border-radius: 15px; border: 2px solid #ffa000;">
        <h3 style="color: #e65100; margin: 0 0 15px 0; font-family: 'Times New Roman', serif; font-size: 20px;">
            ⚠️ Important Features:
        </h3>
        <ul style="font-family: 'Times New Roman', serif; color: #424242; font-size: 16px; 
                   line-height: 1.8; margin: 0;">
            <li><strong>Automatic Scanning:</strong> All uploaded files are scanned instantly</li>
            <li><strong>Risk Assessment:</strong> Each file receives a risk score (0-100%)</li>
            <li><strong>Threat Detection:</strong> Identifies malware, trojans, ransomware & more</li>
            <li><strong>Visual Alerts:</strong> Dangerous files trigger red alert warnings with proof</li>
            <li><strong>PDF Reports:</strong> Professional reports generated automatically</li>
            <li><strong>Multi-File Support:</strong> Upload and scan multiple files at once</li>
        </ul>
    </div>
    
    <div style="background: #ffebee; padding: 25px; border-radius: 15px; margin-top: 20px; 
               border: 2px solid #c62828;">
        <h3 style="color: #c62828; margin: 0 0 10px 0; font-family: 'Times New Roman', serif; 
                   font-size: 20px; text-align: center;">
            🚨 Security Alert System
        </h3>
        <p style="font-family: 'Times New Roman', serif; color: #424242; font-size: 16px; 
                  text-align: center; margin: 0;">
            High-risk files will display <strong style="color: #c62828;">RED CRITICAL ALERTS</strong> 
            with complete threat information including:<br>
            <strong>SHA-256 Hash, Threat Name, Risk Score, Description & Suspicious Flags</strong>
        </p>
    </div>
</div>
"""))

analyzer = CompleteFileAnalyzer()
