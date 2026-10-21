from pathlib import Path
import ast
import sqlite3
from datetime import datetime

root = Path(__file__).resolve().parent
app_path = root / 'app.py'
html_path = root / 'templates' / 'portal.html'
code = app_path.read_text(encoding='utf-8-sig')
html = html_path.read_text(encoding='utf-8-sig')
if 'def download_attachment(' in code:
    raise SystemExit('Uploads are already installed. Restart the server.')
if 'name="content"' not in html or 'submission.content' not in html:
    raise SystemExit('The complete portal.html is required. No files changed.')
tree = ast.parse(code)
factory = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'create_app')
lines = code.splitlines(keepends=True)
replacements = []
blocks = {'assignment_detail': "    @app.route('/assignments/<int:assignment_id>',methods=['GET','POST'])\n    @protected()\n    def assignment_detail(assignment_id):\n        a=assignment_or_404(assignment_id)\n        mine=db().execute('SELECT * FROM submissions WHERE assignment_id=? AND student_id=? ORDER BY attempt DESC',(assignment_id,g.user['id'])).fetchall() if g.user['role']=='student' else []\n        latest=mine[0] if mine else None\n        expired=now()>datetime.fromisoformat(a['due_at'])\n        allowed=not latest or latest['status']=='Revision requested'\n        error=None\n        if request.method=='POST':\n            if g.user['role']!='student': abort(403)\n            content=request.form.get('content','').strip()\n            file_name, file_data, upload_error = None, None, None\n            upload = request.files.get('attachment')\n            if upload and upload.filename:\n                file_name = secure_filename(upload.filename)\n                extension = Path(file_name).suffix.lower()\n                if extension not in {'.pdf', '.doc', '.docx', '.zip'}:\n                    upload_error = 'Choose a PDF, DOC, DOCX or ZIP file.'\n                else:\n                    file_data = upload.stream.read(10 * 1024 * 1024 + 1)\n                    if not file_data:\n                        upload_error = 'The selected file is empty.'\n                    elif len(file_data) > 10 * 1024 * 1024:\n                        upload_error = 'The attachment must be 10 MB or smaller.'\n                    elif extension == '.pdf' and not file_data.startswith(b'%PDF-'):\n                        upload_error = 'The file is not a valid PDF document.'\n                    elif extension == '.doc' and not file_data.startswith(bytes.fromhex('D0CF11E0A1B11AE1')):\n                        upload_error = 'The file is not a supported DOC document.'\n                    elif extension in {'.zip', '.docx'}:\n                        if not zipfile.is_zipfile(io.BytesIO(file_data)):\n                            upload_error = 'The file is not a valid ZIP or DOCX archive.'\n                        elif extension == '.docx':\n                            try:\n                                with zipfile.ZipFile(io.BytesIO(file_data)) as archive:\n                                    if 'word/document.xml' not in archive.namelist() or '[Content_Types].xml' not in archive.namelist():\n                                        upload_error = 'The file is not a Word DOCX document.'\n                            except (zipfile.BadZipFile, ValueError):\n                                upload_error = 'The DOCX document could not be read.'\n            if expired: error='The deadline has passed. Submissions are closed.'\n            elif not allowed: error='Your current submission is awaiting review or already completed.'\n            elif upload_error: error=upload_error\n            elif len(content)>10000: error='Your answer must not exceed 10,000 characters.'\n            elif not file_data and len(content)<20: error='Enter at least 20 characters or attach a homework file.'\n            else:\n                try:\n                    with db():\n                        db().execute('INSERT INTO submissions(assignment_id,student_id,attempt,content,submitted_at,file_name,file_data) VALUES(?,?,?,?,?,?,?)',(assignment_id,g.user['id'],latest['attempt']+1 if latest else 1,content,now().isoformat(),file_name,file_data))\n                    flash('Homework submitted successfully. Your attempt has been saved.')\n                    return redirect(url_for('assignment_detail',assignment_id=assignment_id))\n                except sqlite3.IntegrityError:\n                    error='This attempt was already submitted. Refresh to see the latest version.'\n        submissions=db().execute('SELECT s.*,u.name FROM submissions s JOIN users u ON u.id=s.student_id WHERE s.assignment_id=? ORDER BY s.submitted_at DESC',(assignment_id,)).fetchall() if g.user['role']=='teacher' else []\n        return page('detail',assignment=a,mine=mine,latest=latest,expired=expired,allowed=allowed,submissions=submissions,error=error)\n\n", 'download_attachment': "    @app.get('/submissions/<int:submission_id>/attachment')\n    @protected()\n    def download_attachment(submission_id):\n        item = db().execute('SELECT s.student_id,s.file_name,s.file_data,a.teacher_id FROM submissions s JOIN assignments a ON a.id=s.assignment_id WHERE s.id=?', (submission_id,)).fetchone()\n        if not item:\n            abort(404)\n        permitted = (g.user['role'] == 'student' and item['student_id'] == g.user['id']) or (g.user['role'] == 'teacher' and item['teacher_id'] == g.user['id'])\n        if not permitted:\n            abort(403)\n        if not item['file_name'] or item['file_data'] is None:\n            abort(404)\n        return send_file(io.BytesIO(item['file_data']), as_attachment=True, download_name=item['file_name'], mimetype='application/octet-stream', max_age=0)\n\n", 'error_page': "    @app.errorhandler(403)\n    @app.errorhandler(404)\n    @app.errorhandler(400)\n    @app.errorhandler(413)\n    def error_page(error):\n        message = 'Upload too large. Choose a file of 10 MB or smaller, then return to the assignment and try again.' if error.code == 413 else error.description\n        return page('error',message=message,code=error.code),error.code\n\n"}
for node in factory.body:
    if isinstance(node, ast.FunctionDef) and node.name in ('assignment_detail', 'error_page'):
        start = min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1
        replacements.append((start, node.end_lineno, blocks[node.name]))
if len(replacements) != 2:
    raise SystemExit('Unexpected app structure. No files changed.')
for start, end, replacement in sorted(replacements, reverse=True):
    lines[start:end] = [replacement]
code = ''.join(lines)
code = 'import io\nimport zipfile\nfrom flask import send_file\nfrom werkzeug.utils import secure_filename\n' + code
code = code.replace('MAX_CONTENT_LENGTH=100000', 'MAX_CONTENT_LENGTH=11 * 1024 * 1024')
anchor = "    @app.route('/submissions/<int:submission_id>/review',methods=['GET','POST'])"
if anchor not in code:
    raise SystemExit('Review route not found. No files changed.')
code = code.replace(anchor, blocks['download_attachment'] + '\n' + anchor, 1)
anchor = '        db().executescript(SCHEMA)'
if anchor not in code:
    raise SystemExit('Database initialization not found. No files changed.')
code = code.replace(anchor, anchor + "\n        columns = {row['name'] for row in db().execute('PRAGMA table_info(submissions)')}\n        if 'file_name' not in columns:\n            db().execute('ALTER TABLE submissions ADD COLUMN file_name TEXT')\n        if 'file_data' not in columns:\n            db().execute('ALTER TABLE submissions ADD COLUMN file_data BLOB')", 1)
html = html.replace('<form class="card form-card" method="post"><h2>', '<form class="card form-card" method="post" enctype="multipart/form-data"><h2>')
html = html.replace('name="content" minlength="20" maxlength="10000" required', 'name="content" maxlength="10000"')
html = html.replace('<p class="muted small">20–10,000 characters. Text submissions only.</p>', '<label for="attachment">Attach homework (optional)</label><input id="attachment" name="attachment" type="file" accept=".pdf,.doc,.docx,.zip"><p class="muted small">PDF, Word or ZIP, maximum 10 MB. Compress folders to ZIP. Enter 20 characters OR attach a file. Re-select files after errors; revisions need their own attachment.</p>')
html = html.replace('<details><summary>Read your answer</summary>', "{% if s.file_name %}<p><a class=\"btn outline\" href=\"{{url_for('download_attachment',submission_id=s.id)}}\">Download {{s.file_name}}</a></p>{% endif %}<details><summary>Read your answer</summary>")
html = html.replace('<p class="preserve">{{submission.content}}</p></section>', "<p class=\"preserve\">{{submission.content}}</p>{% if submission.file_name %}<a class=\"btn outline\" href=\"{{url_for('download_attachment',submission_id=submission.id)}}\">Download {{submission.file_name}}</a>{% endif %}</section>")
if 'name="attachment"' not in html or 'multipart/form-data' not in html or html.count("url_for('download_attachment'") < 2:
    raise SystemExit('Template differs from expected. No files changed.')
compile(code, str(app_path), 'exec')
backup = root / ('backup_before_uploads_' + datetime.now().strftime('%Y%m%d_%H%M%S'))
backup.mkdir()
existing_db = root / 'instance' / 'homework.sqlite'
if existing_db.exists():
    with sqlite3.connect(existing_db) as source, sqlite3.connect(backup / 'homework.sqlite') as target:
        source.backup(target)
(backup / 'app.py').write_bytes(app_path.read_bytes())
(backup / 'portal.html').write_bytes(html_path.read_bytes())
app_path.write_text(code, encoding='utf-8')
html_path.write_text(html, encoding='utf-8')
print('Uploads installed. Original code backed up in', backup.name)
print('Restart Flask. Existing accounts and submissions are preserved.')
