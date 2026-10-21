import hmac
import io
import os
import secrets
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BRISBANE = timezone(timedelta(hours=10))
MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".zip"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student', 'teacher'))
);

CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY,
    teacher_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    subject TEXT NOT NULL,
    instructions TEXT NOT NULL,
    due_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    attempt INTEGER NOT NULL,
    content TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Submitted'
        CHECK(status IN ('Submitted', 'Revision requested', 'Completed')),
    feedback TEXT,
    score INTEGER CHECK(score BETWEEN 0 AND 100),
    reviewed_at TEXT,
    UNIQUE(assignment_id, student_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_assignments_teacher
    ON assignments(teacher_id);

CREATE INDEX IF NOT EXISTS idx_submissions_assignment_student
    ON submissions(assignment_id, student_id, attempt DESC);
"""

# Avoid loading attachment bytes when displaying lists or histories.
SUBMISSION_FIELDS = """
    s.id,
    s.assignment_id,
    s.student_id,
    s.attempt,
    s.content,
    s.submitted_at,
    s.status,
    s.feedback,
    s.score,
    s.reviewed_at,
    s.file_name
"""


def now():
    """Return the current time in UTC."""
    return datetime.now(timezone.utc)


def parse_date(value):
    """Read saved timestamps, treating older naive timestamps as UTC."""
    result = datetime.fromisoformat(value)
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def read_attachment(upload):
    """
    Validate one optional attachment.

    These are basic format checks, not antivirus scanning.
    Archives are never extracted or executed.
    """
    if upload is None or not upload.filename:
        return None, None

    filename = secure_filename(upload.filename)
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Choose a PDF, DOC, DOCX or ZIP file.")

    data = upload.stream.read(MAX_FILE_BYTES + 1)

    if not data:
        raise ValueError("The selected file is empty.")

    if len(data) > MAX_FILE_BYTES:
        raise ValueError("The attachment must be 10 MB or smaller.")

    if extension == ".pdf" and not data.startswith(b"%PDF-"):
        raise ValueError("The file is not a valid PDF document.")

    if extension == ".doc" and not data.startswith(
        bytes.fromhex("D0CF11E0A1B11AE1")
    ):
        raise ValueError("The file is not a supported DOC document.")

    if extension in {".zip", ".docx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())

                if extension == ".docx" and not {
                    "[Content_Types].xml",
                    "word/document.xml",
                }.issubset(names):
                    raise ValueError("The file is not a Word DOCX document.")

        except zipfile.BadZipFile:
            raise ValueError("The file is not a valid ZIP or DOCX archive.")

    return filename, data


def create_app(config=None):
    app = Flask(__name__)

    app.config.update(
        DATABASE=str(
            Path(__file__).resolve().parent
            / "instance"
            / "homework.sqlite"
        ),
        MAX_CONTENT_LENGTH=11 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HOMEWORK_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    )

    if config:
        app.config.update(config)

    database = Path(app.config["DATABASE"])
    database.parent.mkdir(parents=True, exist_ok=True)

    # Preserve the session secret across application restarts.
    secret = app.config.get("SECRET_KEY") or os.environ.get("HOMEWORK_SECRET")

    if not secret:
        secret_path = database.parent / ".session-secret"

        try:
            with secret_path.open("x", encoding="utf-8") as output:
                output.write(secrets.token_hex(32))

            secret_path.chmod(0o600)

        except FileExistsError:
            pass

        secret = secret_path.read_text(encoding="utf-8").strip()

    if not secret:
        raise RuntimeError("The session secret must not be empty.")

    app.config["SECRET_KEY"] = secret

    def db():
        """Reuse one database connection per request."""
        if "db" not in g:
            g.db = sqlite3.connect(
                app.config["DATABASE"],
                timeout=15,
            )
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys=ON")

        return g.db

    @app.teardown_appcontext
    def close_db(error):
        connection = g.pop("db", None)

        if connection is not None:
            connection.close()

    # Initialize new installations and upgrade older databases additively.
    with app.app_context():
        db().executescript(SCHEMA)

        columns = {
            row["name"]
            for row in db().execute("PRAGMA table_info(submissions)")
        }

        for name, kind in [
            ("file_name", "TEXT"),
            ("file_data", "BLOB"),
        ]:
            if name not in columns:
                db().execute(
                    f"ALTER TABLE submissions ADD COLUMN {name} {kind}"
                )

        db().commit()

    @app.cli.command("demo-accounts")
    def demo_accounts():
        """Create synthetic accounts without changing existing passwords."""
        accounts = [
            ("Alex Morgan", "student@homework.test", "student"),
            ("Taylor Lee", "teacher@homework.test", "teacher"),
        ]

        for name, email, role in accounts:
            existing = db().execute(
                "SELECT id FROM users WHERE email=?",
                (email,),
            ).fetchone()

            if existing:
                click.echo(f"{email} already exists; password unchanged.")
                continue

            password = secrets.token_urlsafe(14)

            with db():
                db().execute(
                    """
                    INSERT INTO users(name,email,password,role)
                    VALUES(?,?,?,?)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        role,
                    ),
                )

            click.echo(
                f"{role.upper()}: {email}  Password: {password}"
            )

    @app.cli.command("reset-password")
    @click.argument("email")
    @click.password_option(confirmation_prompt=True)
    def reset_password(email, password):
        """Reset an account password through a private terminal prompt."""
        if len(password) < 8:
            raise click.ClickException("Use at least eight characters.")

        with db():
            changed = db().execute(
                "UPDATE users SET password=? WHERE email=?",
                (
                    generate_password_hash(password),
                    email.strip().lower(),
                ),
            )

        if not changed.rowcount:
            raise click.ClickException("Account not found.")

        click.echo("Password updated successfully.")

    @app.before_request
    def load_user():
        session.setdefault("csrf", secrets.token_hex(32))

        if session.get("user_id"):
            g.user = db().execute(
                "SELECT id,name,email,role FROM users WHERE id=?",
                (session["user_id"],),
            ).fetchone()
        else:
            g.user = None

        if request.method == "POST":
            supplied_token = request.form.get("csrf", "")

            if not hmac.compare_digest(
                session["csrf"],
                supplied_token,
            ):
                abort(
                    400,
                    "Form expired. Reload the page and try again.",
                )

    @app.after_request
    def secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' https://images.unsplash.com; "
            "style-src 'self' 'unsafe-inline'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )

        return response

    def protected(role=None):
        """Require authentication and, optionally, a specific role."""
        def decorate(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                if not g.user:
                    return redirect(url_for("login"))

                if role and g.user["role"] != role:
                    abort(403)

                return function(*args, **kwargs)

            return wrapped

        return decorate

    def get_assignment(assignment_id):
        assignment = db().execute(
            "SELECT * FROM assignments WHERE id=?",
            (assignment_id,),
        ).fetchone()

        if not assignment:
            abort(404)

        if (
            g.user["role"] == "teacher"
            and assignment["teacher_id"] != g.user["id"]
        ):
            abort(403)

        return assignment

    def page(view, **data):
        return render_template(
            "portal.html",
            view=view,
            **data,
        )

    @app.template_filter("date")
    def display_date(value):
        if not value:
            return "—"

        return (
            parse_date(value)
            .astimezone(BRISBANE)
            .strftime("%d %b %Y, %I:%M %p")
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            user = db().execute(
                "SELECT * FROM users WHERE email=?",
                (email,),
            ).fetchone()

            if user and check_password_hash(
                user["password"],
                password,
            ):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["csrf"] = secrets.token_hex(32)

                return redirect(url_for("dashboard"))

            error = "Email or password is incorrect. Please try again."

        return page("login", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @protected()
    def dashboard():
        teacher = g.user["role"] == "teacher"

        if teacher:
            rows = db().execute(
                """
                SELECT a.*,
                    (
                        SELECT count(*)
                        FROM submissions s
                        WHERE s.assignment_id=a.id
                          AND s.status='Submitted'
                    ) AS pending
                FROM assignments a
                WHERE teacher_id=?
                ORDER BY a.id DESC
                """,
                (g.user["id"],),
            ).fetchall()

            completed = db().execute(
                """
                SELECT count(*)
                FROM submissions s
                JOIN assignments a ON a.id=s.assignment_id
                WHERE a.teacher_id=?
                  AND s.status='Completed'
                """,
                (g.user["id"],),
            ).fetchone()[0]

            counts = [
                len(rows),
                sum(a["pending"] for a in rows),
                completed,
            ]

        else:
            rows = db().execute(
                """
                SELECT a.*,
                    (
                        SELECT status
                        FROM submissions s
                        WHERE s.assignment_id=a.id
                          AND s.student_id=?
                        ORDER BY attempt DESC
                        LIMIT 1
                    ) AS my_status
                FROM assignments a
                ORDER BY due_at
                """,
                (g.user["id"],),
            ).fetchall()

            counts = [
                sum(not a["my_status"] for a in rows),
                sum(
                    a["my_status"] == "Revision requested"
                    for a in rows
                ),
                sum(
                    a["my_status"] == "Completed"
                    for a in rows
                ),
            ]

        assignments = []

        for row in rows:
            item = dict(row)
            remaining = parse_date(item["due_at"]) - now()

            if remaining.total_seconds() <= 0:
                item["deadline_label"] = "Closed"
            elif remaining <= timedelta(hours=48):
                item["deadline_label"] = "Due soon"
            else:
                item["deadline_label"] = "Open"

            if teacher:
                item["status_label"] = (
                    "Awaiting review"
                    if item["pending"]
                    else item["deadline_label"]
                )
            else:
                item["status_label"] = (
                    item["my_status"] or "Not submitted"
                )

            assignments.append(item)

        subjects = sorted({
            assignment["subject"]
            for assignment in assignments
        })

        query = request.args.get("q", "").strip()[:100]
        subject = request.args.get("subject", "").strip()[:60]
        status = request.args.get("status", "").strip()
        sort = request.args.get(
            "sort",
            "newest" if teacher else "deadline",
        )

        filtered = []

        for assignment in assignments:
            searchable = (
                assignment["title"] + " " + assignment["subject"]
            ).casefold()

            if query and query.casefold() not in searchable:
                continue

            if subject and assignment["subject"] != subject:
                continue

            if status and assignment["status_label"] != status:
                continue

            filtered.append(assignment)

        if sort == "deadline":
            filtered.sort(
                key=lambda assignment: parse_date(
                    assignment["due_at"]
                )
            )

        elif sort == "newest":
            filtered.sort(
                key=lambda assignment: assignment["id"],
                reverse=True,
            )

        elif sort == "review" and teacher:
            filtered.sort(
                key=lambda assignment: (
                    -assignment["pending"],
                    parse_date(assignment["due_at"]),
                )
            )

        return page(
            "dashboard",
            assignments=filtered,
            counts=counts,
            subjects=subjects,
            filters={
                "q": query,
                "subject": subject,
                "status": status,
                "sort": sort,
            },
            total_assignments=len(assignments),
        )

    @app.route("/assignments/new", methods=["GET", "POST"])
    @protected("teacher")
    def new_assignment():
        errors = []

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            subject = request.form.get("subject", "").strip()
            instructions = request.form.get(
                "instructions", ""
            ).strip()

            if not 5 <= len(title) <= 100:
                errors.append(
                    "Title must contain 5–100 characters."
                )

            if not 2 <= len(subject) <= 60:
                errors.append(
                    "Subject must contain 2–60 characters."
                )

            if not 10 <= len(instructions) <= 5000:
                errors.append(
                    "Instructions must contain 10–5000 characters."
                )

            try:
                due = datetime.strptime(
                    request.form.get("due_at", ""),
                    "%Y-%m-%dT%H:%M",
                )
                due = due.replace(
                    tzinfo=BRISBANE
                ).astimezone(timezone.utc)

                if due <= now():
                    errors.append("Choose a future deadline.")

            except ValueError:
                errors.append("Enter a valid deadline.")

            if not errors:
                with db():
                    result = db().execute(
                        """
                        INSERT INTO assignments(
                            teacher_id,
                            title,
                            subject,
                            instructions,
                            due_at,
                            created_at
                        )
                        VALUES(?,?,?,?,?,?)
                        """,
                        (
                            g.user["id"],
                            title,
                            subject,
                            instructions,
                            due.isoformat(),
                            now().isoformat(),
                        ),
                    )

                flash(
                    "Assignment published. "
                    "Students can now submit their work."
                )

                return redirect(
                    url_for(
                        "assignment_detail",
                        assignment_id=result.lastrowid,
                    )
                )

        return page("new", errors=errors)

    @app.route(
        "/assignments/<int:assignment_id>",
        methods=["GET", "POST"],
    )
    @protected()
    def assignment_detail(assignment_id):
        assignment = get_assignment(assignment_id)
        error = None

        if request.method == "POST":
            if g.user["role"] != "student":
                abort(403)

            content = request.form.get("content", "").strip()

            try:
                filename, data = read_attachment(
                    request.files.get("attachment")
                )

                if len(content) > 10000:
                    raise ValueError(
                        "Your answer must not exceed 10,000 characters."
                    )

                if data is None and len(content) < 20:
                    raise ValueError(
                        "Enter at least 20 characters "
                        "or attach a homework file."
                    )

                # Lock before checking state and creating an attempt.
                # This prevents competing requests from creating
                # conflicting submission versions.
                with db():
                    db().execute("BEGIN IMMEDIATE")

                    latest = db().execute(
                        """
                        SELECT attempt,status
                        FROM submissions
                        WHERE assignment_id=?
                          AND student_id=?
                        ORDER BY attempt DESC
                        LIMIT 1
                        """,
                        (assignment_id, g.user["id"]),
                    ).fetchone()

                    if now() >= parse_date(assignment["due_at"]):
                        raise ValueError(
                            "The deadline has passed. "
                            "Submissions are closed."
                        )

                    if (
                        latest
                        and latest["status"] != "Revision requested"
                    ):
                        raise ValueError(
                            "Your current submission is awaiting "
                            "review or already completed."
                        )

                    attempt = (
                        latest["attempt"] + 1 if latest else 1
                    )

                    db().execute(
                        """
                        INSERT INTO submissions(
                            assignment_id,
                            student_id,
                            attempt,
                            content,
                            submitted_at,
                            file_name,
                            file_data
                        )
                        VALUES(?,?,?,?,?,?,?)
                        """,
                        (
                            assignment_id,
                            g.user["id"],
                            attempt,
                            content,
                            now().isoformat(),
                            filename,
                            data,
                        ),
                    )

                flash(
                    "Homework submitted successfully. "
                    "Your attempt has been saved."
                )

                return redirect(
                    url_for(
                        "assignment_detail",
                        assignment_id=assignment_id,
                    )
                )

            except ValueError as exc:
                error = str(exc)

            except sqlite3.IntegrityError:
                error = (
                    "This attempt was already submitted. "
                    "Refresh to see the latest version."
                )

        if g.user["role"] == "student":
            mine = db().execute(
                f"""
                SELECT {SUBMISSION_FIELDS}
                FROM submissions s
                WHERE s.assignment_id=?
                  AND s.student_id=?
                ORDER BY s.attempt DESC
                """,
                (assignment_id, g.user["id"]),
            ).fetchall()
        else:
            mine = []

        latest = mine[0] if mine else None

        if g.user["role"] == "teacher":
            submissions = db().execute(
                f"""
                SELECT {SUBMISSION_FIELDS},u.name
                FROM submissions s
                JOIN users u ON u.id=s.student_id
                WHERE s.assignment_id=?
                ORDER BY
                    CASE
                        WHEN s.status='Submitted' THEN 0
                        ELSE 1
                    END,
                    s.submitted_at DESC
                """,
                (assignment_id,),
            ).fetchall()
        else:
            submissions = []

        return page(
            "detail",
            assignment=assignment,
            mine=mine,
            latest=latest,
            expired=now() >= parse_date(assignment["due_at"]),
            allowed=(
                not latest
                or latest["status"] == "Revision requested"
            ),
            submissions=submissions,
            error=error,
        )

    @app.get("/submissions/<int:submission_id>/attachment")
    @protected()
    def download_attachment(submission_id):
        item = db().execute(
            """
            SELECT s.student_id,s.file_name,a.teacher_id
            FROM submissions s
            JOIN assignments a ON a.id=s.assignment_id
            WHERE s.id=?
            """,
            (submission_id,),
        ).fetchone()

        if not item:
            abort(404)

        permitted = (
            g.user["role"] == "student"
            and item["student_id"] == g.user["id"]
        ) or (
            g.user["role"] == "teacher"
            and item["teacher_id"] == g.user["id"]
        )

        if not permitted:
            abort(403)

        if not item["file_name"]:
            abort(404)

        data = db().execute(
            "SELECT file_data FROM submissions WHERE id=?",
            (submission_id,),
        ).fetchone()["file_data"]

        if data is None:
            abort(404)

        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=item["file_name"],
            mimetype="application/octet-stream",
            max_age=0,
        )

    @app.route(
        "/submissions/<int:submission_id>/review",
        methods=["GET", "POST"],
    )
    @protected("teacher")
    def review(submission_id):
        submission = db().execute(
            f"""
            SELECT
                {SUBMISSION_FIELDS},
                u.name,
                a.title,
                a.teacher_id,
                a.due_at
            FROM submissions s
            JOIN users u ON u.id=s.student_id
            JOIN assignments a ON a.id=s.assignment_id
            WHERE s.id=?
            """,
            (submission_id,),
        ).fetchone()

        if not submission:
            abort(404)

        if submission["teacher_id"] != g.user["id"]:
            abort(403)

        error = None

        if request.method == "POST":
            feedback = request.form.get("feedback", "").strip()
            decision = request.form.get("decision", "")
            raw_score = request.form.get("score", "").strip()

            try:
                score = int(raw_score) if raw_score else None
            except ValueError:
                score = -1

            if not 10 <= len(feedback) <= 3000:
                error = "Feedback must contain 10–3000 characters."

            elif decision not in (
                "Revision requested",
                "Completed",
            ):
                error = "Choose a valid review decision."

            elif score is not None and not 0 <= score <= 100:
                error = (
                    "Score must be a whole number from 0 to 100."
                )

            elif decision == "Completed" and score is None:
                error = "Enter a score to complete the review."

            elif (
                decision == "Revision requested"
                and now() >= parse_date(submission["due_at"])
            ):
                error = (
                    "The deadline has passed. "
                    "A revision cannot be requested; "
                    "complete the review instead."
                )

            else:
                # Only an unreviewed attempt can change state.
                with db():
                    result = db().execute(
                        """
                        UPDATE submissions
                        SET feedback=?,
                            score=?,
                            status=?,
                            reviewed_at=?
                        WHERE id=?
                          AND status='Submitted'
                        """,
                        (
                            feedback,
                            score,
                            decision,
                            now().isoformat(),
                            submission_id,
                        ),
                    )

                if not result.rowcount:
                    error = (
                        "This attempt has already been reviewed. "
                        "Refresh to see the saved review."
                    )
                else:
                    flash(
                        "Feedback published. "
                        "The student can now view your review."
                    )

                    return redirect(
                        url_for(
                            "assignment_detail",
                            assignment_id=submission["assignment_id"],
                        )
                    )

        return page(
            "review",
            submission=submission,
            error=error,
        )

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def error_page(error):
        if error.code == 413:
            message = (
                "Upload too large. Choose a file of 10 MB or smaller, "
                "then return to the assignment and try again."
            )
        else:
            message = error.description

        return (
            page(
                "error",
                message=message,
                code=error.code,
            ),
            error.code,
        )

    return app


if __name__ == "__main__":
    create_app().run()