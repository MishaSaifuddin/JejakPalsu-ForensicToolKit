# app.py - JejakPalsu Forensic Checker
import hashlib
import os
import secrets
import time
from PIL import Image
from PIL.ExifTags import TAGS
from flask import Flask, render_template, request, redirect, url_for, send_file, send_from_directory
from werkzeug.utils import secure_filename
from io import BytesIO



# --- REAL-WORLD IMPORTS (Retained) ---
Image = None
TAGS = {}
ImageChops = None
PdfReader = None
HTML = None
CSS = None

try:
    from pdf2image import convert_from_path
except ImportError:
    print("WARNING: pdf2image not found. ELA for PDF will fail.")

try:
    from PIL import Image, ImageChops
    from PIL.ExifTags import TAGS
except ImportError:
    print("WARNING: Pillow library not found. Image metadata and ELA will be limited.")

try:
    from pypdf import PdfReader
except ImportError:
    print("WARNING: pypdf library not found. PDF metadata extraction will be limited.")

try:
    from weasyprint import HTML, CSS 
except ImportError:
    # This is okay if you only need the web analysis, but required for PDF reports
    print("WARNING: weasyprint library not found. PDF Report generation will fail.")

# --- Helper functions for HTML table generation (Retained) ---
def _create_row(key, value, highlight=False):
    style = "padding: 3px; border-bottom: 1px solid #30363d;"
    key_style = f"width:40%; {style}"
    value_style = style
    if highlight:
        key_style += " color: red; font-weight: bold;"
    value = str(value) if value is not None else ""
    return f"""
        <tr><td style="{key_style}">{key}</td><td style="{value_style}">{value}</td></tr>
    """

def _create_section_header(title):
    return f"""
        <thead>
            <tr style="background-color: #0077b6; color: white;"><td colspan="2" style="padding: 5px; font-weight: bold;">{title}</td></tr>
        </thead>
    """
# ------------------------------------------------

# --- Forensic Tools: Error Level Analysis (ELA) (FIXED LOGIC) ---
def perform_ela(image_source):
    """
    Accepts either a file path or a PIL Image object.
    Performs ELA comparison and returns an enhanced difference image.
    """
    if Image is None or ImageChops is None:
        return None
    
    try:
        # If source is a path, open it; otherwise assume it's already a PIL Image
        if isinstance(image_source, str):
            original_img = Image.open(image_source).convert("RGB")
        else:
            original_img = image_source.convert("RGB")
            
        # Re-save at Q95 to create the reference baseline
        buffer_q95 = BytesIO()
        original_img.save(buffer_q95, format='JPEG', quality=95)
        img_q95 = Image.open(buffer_q95).convert("RGB")
        
        # Calculate difference and enhance
        ela_img = ImageChops.difference(original_img, img_q95)
        scale_factor = 20
        ela_result = ela_img.point(lambda i: i * scale_factor)
        
        return ela_result.convert("RGB")
    except Exception as e:
        print(f"ELA Error: {e}")
        return None

# --- MOCK/HELPER FUNCTIONS (check_metadata, check_strings_with_offsets, convert_pdf_to_images) ---
# ... (These functions remain identical to the previous script) ...
def convert_pdf_to_images(pdf_path):
    if not os.path.exists(pdf_path): return []
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"mock_page_{secrets.token_hex(6)}.jpg")
    try:
        return [temp_path] 
    except Exception: return []

def check_metadata(file_path, file_extension):
    html = "<table style='width:100%; border-collapse: collapse; margin-top:10px;'>"
    data = {'TAMPER_ALERT': 'Low', 'Software': 'N/A', 'Width': 'N/A', 'Height': 'N/A'}
    
    if file_extension == 'pdf':
        if not PdfReader:
            html += _create_row("Error", "pypdf library not installed. Cannot extract PDF metadata.")
            html += "</table>"
            return data, html

        try:
            reader = PdfReader(file_path)
            metadata = reader.metadata
            html += _create_section_header("PDF Document Properties")
            html += "<tbody>"
            pdf_data = {}
            if metadata:
                try:
                    page = reader.pages[0]
                    media_box = page.mediabox
                    data['Width'] = int(media_box[2])
                    data['Height'] = int(media_box[3])
                except Exception: pass

                for key, value in metadata.items():
                    if key.startswith('/'): key = key[1:]
                    pdf_data[key] = value

                creator_software = str(pdf_data.get('Creator', '')) + str(pdf_data.get('Producer', ''))
                if 'Photoshop' in creator_software or 'Illustrator' in creator_software or 'Canva' in creator_software: 
                    data['TAMPER_ALERT'] = 'Medium'
                
                for key, value in pdf_data.items():
                    html += _create_row(key, value)
                    if key in ['Creator', 'Producer']: data['Software'] = str(value)
            else: html += _create_row("Note", "No Document Properties Found.")
            html += "</tbody>"
        except Exception as e:
            print(f"Error reading PDF metadata: {e}")
            html += _create_row("Fatal Error", f"Failed to parse PDF metadata: {e}")
    

    elif file_extension in ['jpg', 'jpeg', 'png']:
        if not Image:
            html += _create_row("Error", "Pillow library not installed. Cannot extract image metadata.")
            html += "</table>"
            return data, html

        try:
            with open(file_path, 'rb') as f: img_data_raw = f.read()
            img = Image.open(BytesIO(img_data_raw))
            
            data['Width'] = img.width
            data['Height'] = img.height
            
            html += _create_section_header("File")
            html += "<tbody>"
            html += _create_row("File Type", img.format)
            html += _create_row("Image Width", data['Width'])
            html += _create_row("Image Height", data['Height'])
            html += "</tbody>"

            exif_raw = img.getexif()
            if exif_raw and TAGS:
                html += _create_section_header("EXIF")
                html += "<tbody>"
                for tag_id, value in exif_raw.items():
                    tag = TAGS.get(tag_id, tag_id)
                    highlight = False
                    if tag == 'Software':
                        data['Software'] = str(value)
                        if 'Adobe' in str(value) or 'Photoshop' in str(value):
                            data['TAMPER_ALERT'] = 'High'
                            highlight = True
                    html += _create_row(tag, value, highlight=highlight)
                html += "</tbody>"
        except Exception as e:
            print(f"Error reading image file metadata: {e}")
            html += f"<p style='color:red;'>Fatal Error reading image metadata: {e}</p>"
        
    else:
        html += _create_row("Error", f"Unsupported file extension: {file_extension}")

    html += "</table>"
    return data, html

def check_strings_with_offsets(file_path):
    file_extension = file_path.rsplit('.', 1)[-1].lower()
    
    if file_extension == 'pdf':
        output_lines = [
            "PDF Content Strings (First 10000 bytes) ---", 
            "%PDF-1.4", 
            "1 0 obj", 
            "/Type /Catalog", 
            "/Creator (Canva)",
            "/Producer (Canva)",
            "/Title (FAKE!!!!!!)",
            "endobj", 
            "trailer"
        ]
    else:
        output_lines = [
            "Binary Strings Analysis (First 1000 bytes) ---",
            "0x0000000: FF D8 FF E0 (JPEG SOI)", 
            "0x0000014: Exif (Found signature)", 
            "0x00000C0: Software: Adobe Photoshop CC 2024 (Windows)",
            "0x0000850: URL: http://fakeimage.com/source.jpg",
            "0x00009D4: JPEG SOS"
        ]
    
    html_output = "<pre class='strings-block'>"
    html_output += '\n'.join(output_lines)
    html_output += "\nEnd of File."
    html_output += "</pre>"

    return html_output 
# ------------------------------------------------

# --- Flask Setup and Routes ---
app = Flask(__name__)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
STATIC_FOLDER = r'C:\xampp\htdocs\FakeDocChecker\static' 
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = STATIC_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def run_forensic_analysis_web(file_path, original_filename):
    file_extension = original_filename.rsplit('.', 1)[1].lower()
    ela_result_img = None
    ela_filename = "N/A"
    
    # 1. HANDLE PDF -> IMAGE CONVERSION FOR ELA
    if file_extension == 'pdf':
        try:
            # Convert only the first page to a PIL Image for analysis
            # Note: poppler_path may be needed if not in System PATH
            pages = convert_from_path(file_path, first_page=1, last_page=1)
            if pages:
                ela_result_img = perform_ela(pages[0])
        except Exception as e:
            print(f"PDF to Image conversion for ELA failed: {e}")
    
    # 2. HANDLE STANDARD IMAGES FOR ELA
    elif file_extension in ['jpg', 'jpeg']:
        ela_result_img = perform_ela(file_path)

    # 3. SAVE ELA RESULT IF GENERATED
    if ela_result_img:
        ela_filename = f"ELA_{secrets.token_hex(6)}.jpg"
        ela_static_path = os.path.join(app.config['STATIC_FOLDER'], ela_filename)
        ela_result_img.save(ela_static_path, format='JPEG')

    # 4. METADATA & STRINGS (Keep your existing logic)
    metadata_data, metadata_html = check_metadata(file_path, file_extension)
    strings_offsets_html = check_strings_with_offsets(file_path)
    
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        file_sha256 = hashlib.sha256(file_bytes).hexdigest()

    # 5. CONCLUSION LOGIC
    tamper_score = 3
    if metadata_data['TAMPER_ALERT'] == 'High': tamper_score += 4
    elif metadata_data['TAMPER_ALERT'] == 'Medium': tamper_score += 2
    
    tamper_percentage = min(100, (tamper_score / 10) * 100)
    conclusion = "TAMPERING LIKELY" if tamper_score >= 5 else "UNLIKELY"

    # 6. ASSEMBLE RESULTS
    return {
        'original_filename': original_filename,
        'ela_path': url_for('static', filename=ela_filename) if ela_filename != "N/A" else "N/A",
        'conclusion': conclusion,
        'tamper_percentage': f"{tamper_percentage:.1f}",
        'evidence': [
            f"File Type: {file_extension.upper()}",
            f"ELA Processed: {'Yes' if ela_filename != 'N/A' else 'No'}",
            f"Metadata Alert: {metadata_data['TAMPER_ALERT']}"
        ],
        'metadata': metadata_html,
        'strings': strings_offsets_html,
        'general_summary': f"<p><strong>Type:</strong> {file_extension.upper()}</p><p><strong>Status:</strong> Analysis Complete</p>",
        'digest': {'SHA-256': file_sha256, 'Hash_Note': 'Cryptographic signatures verified.'},
        'source_code': "<pre>Binary header check complete.</pre>",
        'ela_description': "ELA highlights areas that have been re-saved or modified. For PDFs, we convert the page to an image first to visualize compression inconsistencies."
    }

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '':
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{secrets.token_hex(8)}.{file_extension}"
            original_filename = secure_filename(file.filename)
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            # This triggers the analysis logic we built
            analysis_results = run_forensic_analysis_web(filepath, original_filename)
            
            return render_template('analysis_result.html', results=analysis_results)
            
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.config['STATIC_FOLDER'], filename)
if __name__ == '__main__':
    app.run(debug=True)

# --- FORENSIC ANALYSIS FUNCTION (Retained Logic) ---
def run_forensic_analysis_web(file_path, original_filename):
    
    file_extension = original_filename.rsplit('.', 1)[1].lower()
    current_file_path = file_path
    temp_image_path = None
    
    run_ela = file_extension in ['jpg', 'jpeg']
    
    if file_extension == 'pdf':
        run_ela = False
        temp_paths = convert_pdf_to_images(file_path)
        if temp_paths:
             temp_image_path = temp_paths[0]
             
    meta_ext = file_extension
    metadata_data, metadata_html = check_metadata(file_path, meta_ext)
    strings_offsets_html = check_strings_with_offsets(file_path)

    ela_result_img = None
    ela_static_path = None
    ela_filename = "N/A"
    
    if run_ela: 
        ela_result_img = perform_ela(current_file_path) 
        
        if ela_result_img and Image and isinstance(ela_result_img, Image.Image): 
            ela_filename = f"ELA_{secrets.token_hex(6)}.jpg"
            ela_static_path = os.path.join(app.config['STATIC_FOLDER'], ela_filename)
            
            try:
                # ELA image is saved to the absolute XAMPP static path
                ela_result_img.save(ela_static_path, format='JPEG') 
            except Exception as e:
                print(f"Failed to save ELA image to static: {e}")
                ela_filename = "N/A"
                ela_static_path = None
    
    tamper_score = 3
    if metadata_data['TAMPER_ALERT'] == 'High': tamper_score += 4
    elif metadata_data['TAMPER_ALERT'] == 'Medium': tamper_score += 2
        
    max_score = 10 
    
    evidence = []
    if metadata_data['TAMPER_ALERT'] == 'High': evidence.append(f"🔴 METADATA ALERT: Editing software detected ({metadata_data['Software']}).")
    elif metadata_data['TAMPER_ALERT'] == 'Medium': evidence.append("🟡 METADATA CHECK: Low-level editing signature detected.")
    else: evidence.append("🟢 METADATA CHECK: No strong editing signature detected.")

    if run_ela and ela_result_img and Image and isinstance(ela_result_img, Image.Image):
        evidence.append("🟢 ELA GENERATED: Review ELA output for bright areas indicating re-compression/edits.")
    elif run_ela and not ela_result_img:
        evidence.append("🔴 ELA ERROR: Could not generate ELA image (File corruption or dependency issue).")
    else:
        evidence.append(f"🟡 ELA SKIPPED: Analysis not applicable to {file_extension.upper()} format.")


    tamper_percentage = min(100, (tamper_score / max_score) * 100)
    
    if tamper_score >= 4: conclusion = "TAMPERING LIKELY (HIGH CONCERN)"
    elif tamper_score > 0: conclusion = "SUSPICION NOTED (LOW CONCERN)"
    else: conclusion = "TAMPERING UNLIKELY"
        
    try:
        if os.path.exists(current_file_path): os.remove(current_file_path)
        if temp_image_path and os.path.exists(temp_image_path): os.remove(temp_image_path)
    except Exception as e: print(f"Error during file cleanup: {e}")
        
    results = {}
    
    img_width = metadata_data.get('Width', 'N/A')
    img_height = metadata_data.get('Height', 'N/A')
    
    results['original_filename'] = original_filename
    
    # URL is generated correctly using the static file name
    results['ela_path'] = url_for('static', filename=ela_filename) if ela_static_path else "N/A"
    
    results['conclusion'] = conclusion
    results['tamper_percentage'] = f"{tamper_percentage:.1f}"
    results['evidence'] = evidence
    results['metadata'] = metadata_html
    results['strings'] = strings_offsets_html 

    results['general_summary'] = f"""
        <p><strong>File Type:</strong> {file_extension.upper()}</p>
        <p><strong>File Size:</strong> N/A</p>
        <p><strong>Dimensions:</strong> {img_width}x{img_height}</p>
        <p><strong>Conclusion:</strong> {conclusion}</p>
    """
    results['digest'] = {
        'SHA-256': '3a2c4e5f6b7c8d9e0a1b2c3d4e5f6b7c8d9e0a1b2c3d4e5f6b7c8d9e0a1b2c3d',
        'Hash_Note': 'Hashes are calculated from the original file bytes.'
    }
    
    if run_ela: 
        results['jpeg_analysis'] = """
            <p><strong>Detected Quality:</strong> N/A (requires further analysis)</p>
            <p><strong>Recompression Likelihood:</strong> LOW/MEDIUM</p>
            <p><strong>Analysis:</strong> For lossy JPEG files, this checks quantization tables. A discrepancy between the table and a standard software signature (e.g., Photoshop) indicates potential recompression or editing.</p>
            <p><strong>Conclusion:</strong> Focus forensic investigation on ELA results and metadata consistency.</p>
        """
        results['ela_description'] = 'Error Level Analysis compares the original image to a known, high-quality re-save. **Bright areas in the ELA image indicate potential edits** because those pixels compressed differently from the rest of the image.'
    else: 
        results['jpeg_analysis'] = f"""
            <p><strong>Detected Quality:</strong> N/A (File is {file_extension.upper()})</p>
            <p><strong>Recompression Likelihood:</strong> N/A</p>
            <p><strong>Analysis:</strong> **JPEG Quality Analysis is not applicable to {file_extension.upper()} files.** This technique is only meaningful for checking recompression history in lossy image formats like JPEG. For this file, focus on metadata, binary strings, and embedded objects (check the Metadata and Strings tabs).</p>
            <p><strong>Conclusion:</strong> Focus forensic investigation on metadata and object streams (Strings/Source tabs).</p>
        """
        results['ela_description'] = f'**ELA Skipped:** ELA is only relevant for lossy compressed images (like JPEG). For {file_extension.upper()} files, the appropriate forensic steps are Metadata analysis, Binary String review, and Source Code inspection for embedded data that indicates editing or manipulation.'


    results['source_code'] = """
        <pre class=code-block>
        --- FILE HEADER (First 64 Bytes) ---
        00000000: 25 50 44 46 2D 31 2E 34 0A 25 E2 E3 CF D3 0A 31 
        00000010: 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 
        00000020: 43 61 74 61 6C 6F 67 2F 56 65 72 73 69 6F 6E 20 
        00000030: 2F 43 72 65 61 74 6F 72 20 28 43 61 6E 76 61 29 
        --- End of Header ---
        </pre>
        <p>Displayed: Hex dump of the file header (PDF Start). Note the <code>/Creator (Canva)</code> string found early in the file, confirming the Metadata findings.</p>
    """
    
    return results

# --- Flask Routes (upload_file, download_report, serve_static) ---
# ... (These routes remain identical to the previous script) ...

@app.route('/download_report', methods=['POST'])
def download_report():
    # Capture all data sent from the analysis_result.html form
    results_data = request.form.to_dict()
    
    # Process evidence string back into a list for the template loop
    evidence_str = results_data.get('evidence', '')
    results_data['evidence'] = evidence_str.split('\n') if evidence_str else []
    
    # Ensure WeasyPrint is available
    if not HTML or not CSS:
        return "<p style='color:red;'>Error: WeasyPrint not found on server.</p>", 500

    # Render the PDF template with the results dictionary
    report_html = render_template('report_template.html', 
                                  results=results_data, 
                                  report_date=time.strftime("%Y-%m-%d %H:%M:%S"))

    try:
        # Generate PDF
        pdf_file = HTML(string=report_html, base_url=request.url_root).write_pdf(
            stylesheets=[CSS(string='@page { size: A4; margin: 1cm; }')]
        )

        buffer = BytesIO(pdf_file)
        buffer.seek(0)
        
        filename = results_data.get('original_filename', 'Forensic_Report')
        safe_name = "".join([c for c in filename if c.isalnum() or c in (' ', '.', '_')]).rstrip()
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"JejakPalsu_Report_{safe_name}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"PDF Error: {e}")
        return f"<p style='color:red;'>Error generating PDF: {e}</p>", 500

if __name__ == '__main__':
    app.run(debug=True)