import collections
import io
import os
import re
import shlex
import subprocess
import threading
import uuid
import zipfile
from typing import Any, Dict, List, Tuple

from flask import Flask, abort, jsonify, request, send_file

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "sbom-web-secret")
DELETE_IMAGE_AFTER_SUCCESS = os.environ.get("DELETE_IMAGE_AFTER_SUCCESS", "false").lower() in {
    "1",
    "true",
    "yes",
}
SBOM_OUTPUT_DIR = os.environ.get("SBOM_OUTPUT_DIR", "/tmp/sboms")
ZIP_COMPRESSION = zipfile.ZIP_DEFLATED if hasattr(zipfile, "ZIP_DEFLATED") else zipfile.ZIP_STORED
TRIVY_SKIP_DB_UPDATE_DEFAULT = os.environ.get("TRIVY_SKIP_DB_UPDATE", "true")
TRIVY_SKIP_POLICY_UPDATE_DEFAULT = os.environ.get("TRIVY_SKIP_POLICY_UPDATE", "true")
TRIVY_NO_PROGRESS_DEFAULT = os.environ.get("TRIVY_NO_PROGRESS", "true")
TRIVY_DISABLE_TELEMETRY_DEFAULT = os.environ.get("TRIVY_DISABLE_TELEMETRY", "true")
app.config["PROPAGATE_EXCEPTIONS"] = False


SUPPORTED_TOOLS: Dict[str, str] = {
    "syft": "Syft",
    "trivy": "Trivy",
}

SUPPORTED_FORMATS: Dict[str, Dict[str, str]] = {
    "spdx": {
        "label": "SPDX (JSON)",
        "syft": "spdx-json",
        "trivy": "spdx-json",
        "extension": "json",
    },
    "cyclonedx": {
        "label": "CycloneDX (JSON)",
        "syft": "cyclonedx-json",
        "trivy": "cyclonedx",
        "extension": "json",
    },
}

MAX_DOWNLOAD_CACHE = 25
DOWNLOAD_CACHE: "collections.OrderedDict[str, Tuple[Any, str, str]]" = collections.OrderedDict()


def _humanize_error(raw: str) -> str:
    """Return a shorter, user-friendly error message."""
    text = raw.lower()
    if "authentication required" in text or "could not determine source" in text or "manifest unknown" in text:
        return "指定された Docker イメージが見つからないか、アクセスできません。イメージ名や認証を確認してください。"
    if "docker daemon" in text or "connect to docker daemon" in text:
        return "Docker デーモンに接続できません。Docker が起動しているか確認してください。"
    if "timeout" in text:
        return "処理がタイムアウトしました。イメージサイズやネットワーク状況を確認してください。"
    return raw


def _build_command(tool: str, image: str, sbom_format: str) -> List[str]:
    """Create the CLI command for the requested tool/format combination."""
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool: {tool}")
    if sbom_format not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {sbom_format}")

    if tool == "syft":
        output_flag = SUPPORTED_FORMATS[sbom_format][tool]
        return ["syft", image, "-o", output_flag]

    format_flag = SUPPORTED_FORMATS[sbom_format][tool]
    # Trivy: generate SBOM via image scan from remote registry (container cannot access host Docker daemon).
    return [
        "trivy",
        "image",
        "--format",
        format_flag,
        "--image-src=remote",
        image,
    ]


def _build_filename(image_ref: str, tool: str, sbom_format: str) -> str:
    """Generate a descriptive, filesystem-safe SBOM filename."""
    cleaned_image = image_ref.strip() or "sbom"
    cleaned_image = cleaned_image.replace("docker.io/", "").replace("index.docker.io/", "")
    cleaned_image = re.sub(r"[^A-Za-z0-9_.:/-]+", "-", cleaned_image)
    cleaned_image = cleaned_image.replace("/", "-").replace(":", "-").replace("@", "-")
    safe_image = re.sub(r"-{2,}", "-", cleaned_image).strip("-") or "sbom"
    extension = SUPPORTED_FORMATS[sbom_format].get("extension", "json")
    return f"{safe_image}-{tool}-{sbom_format}.{extension}"


def _write_sbom_to_disk(sbom_output: str, filename: str) -> str:
    """Persist SBOM content to disk and return the saved path."""
    os.makedirs(SBOM_OUTPUT_DIR, exist_ok=True)
    saved_path = os.path.join(SBOM_OUTPUT_DIR, f"{uuid.uuid4().hex}-{filename}")
    with open(saved_path, "w", encoding="utf-8") as fp:
        fp.write(sbom_output)
    return saved_path


def _write_bytes_to_disk(payload: bytes, filename: str) -> str:
    """Persist binary content (e.g., ZIP) to disk and return the saved path."""
    os.makedirs(SBOM_OUTPUT_DIR, exist_ok=True)
    saved_path = os.path.join(SBOM_OUTPUT_DIR, f"{uuid.uuid4().hex}-{filename}")
    with open(saved_path, "wb") as fp:
        fp.write(payload)
    return saved_path


def _cleanup_image(image_ref: str) -> str:
    """Attempt to delete the pulled image via Docker CLI if configured."""
    if not DELETE_IMAGE_AFTER_SUCCESS:
        return "Image cleanup skipped (DELETE_IMAGE_AFTER_SUCCESS not enabled)."

    command = ["docker", "image", "rm", "-f", image_ref]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return "Docker CLI not available in container; cannot remove image."
    except subprocess.TimeoutExpired:
        return "Image cleanup timed out."

    if completed.returncode == 0:
        return f"Removed image: {image_ref}"

    stderr_output = completed.stderr.strip()
    stdout_output = completed.stdout.strip()
    details = "\n".join(filter(None, [stdout_output, stderr_output]))
    return f"Image cleanup failed: {details or 'unknown error'}"


def _cache_download(data: str | bytes, filename: str, mimetype: str = "application/json") -> str:
    """Store downloadable content in memory so the user can fetch it without re-generation."""
    token = uuid.uuid4().hex
    DOWNLOAD_CACHE[token] = (data, filename, mimetype)
    if len(DOWNLOAD_CACHE) > MAX_DOWNLOAD_CACHE:
        oldest_token = next(iter(DOWNLOAD_CACHE))
        DOWNLOAD_CACHE.pop(oldest_token, None)
    return token


def _safe_image_folder(image_ref: str) -> str:
    """Sanitize an image reference for use as a folder name inside the ZIP."""
    cleaned_image = image_ref.replace("docker.io/", "").replace("index.docker.io/", "")
    cleaned_image = re.sub(r"[^A-Za-z0-9_.:/-]+", "-", cleaned_image)
    cleaned_image = cleaned_image.replace("/", "-").replace(":", "-").replace("@", "-")
    return re.sub(r"-{2,}", "-", cleaned_image).strip("-") or "image"


def _prepare_single_entry(image_ref: str) -> Dict[str, Any]:
    """Normalize a single user-provided image reference into the entry shape."""
    ref = (image_ref or "").strip()
    if not ref:
        raise ValueError("Docker image reference is required.")
    tag = "latest"
    if ":" in ref and not ref.endswith(":/"):
        _, _, tail = ref.partition("/")
        name_part = tail or ref
        if ":" in name_part:
            tag = name_part.split(":", 1)[1] or "latest"
    return {"name": ref, "image_ref": ref, "tag": tag, "pull_count": None, "description": ""}


def _build_env(registry_username: str = "", registry_password: str = "") -> Dict[str, str]:
    """Build environment for registry auth if provided."""
    env = os.environ.copy()
    # Avoid per-run Trivy DB/telemetry overhead for multi-pattern generation unless explicitly overridden.
    env.setdefault("TRIVY_SKIP_DB_UPDATE", TRIVY_SKIP_DB_UPDATE_DEFAULT)
    env.setdefault("TRIVY_SKIP_POLICY_UPDATE", TRIVY_SKIP_POLICY_UPDATE_DEFAULT)
    env.setdefault("TRIVY_NO_PROGRESS", TRIVY_NO_PROGRESS_DEFAULT)
    env.setdefault("TRIVY_DISABLE_TELEMETRY", TRIVY_DISABLE_TELEMETRY_DEFAULT)
    if registry_username:
        env["SYFT_REGISTRY_AUTH_USERNAME"] = registry_username
        env["TRIVY_USERNAME"] = registry_username
    if registry_password:
        env["SYFT_REGISTRY_AUTH_PASSWORD"] = registry_password
        env["TRIVY_PASSWORD"] = registry_password
    return env


def _ensure_image_cached(image_ref: str, extra_env: Dict[str, str] | None = None) -> str:
    """Best-effort: avoid repeated pulls by checking local cache; pull if missing.
    
    Note: When running inside a container without Docker socket access, this will
    quickly return as Docker CLI won't be able to connect to the daemon.
    """
    env = _build_env(**(extra_env or {}))
    
    # Quick check: if docker command doesn't exist, skip immediately
    inspect_cmd = ["docker", "version"]
    try:
        version_check = subprocess.run(
            inspect_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,  # Very short timeout for version check
            env=env,
        )
        if version_check.returncode != 0:
            return "Docker daemon not accessible; tool will fetch image directly."
    except FileNotFoundError:
        return "Docker CLI not available; tool will fetch image directly."
    except subprocess.TimeoutExpired:
        return "Docker not responding; tool will fetch image directly."

    # Docker is available, check if image exists
    inspect_cmd = ["docker", "image", "inspect", image_ref]
    try:
        inspected = subprocess.run(
            inspect_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "Image inspect timed out; tool will fetch image directly."

    if inspected.returncode == 0:
        return "Image already present locally."

    pull_cmd = ["docker", "pull", image_ref]
    try:
        pulled = subprocess.run(
            pull_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return "Image pull timed out; tool will attempt to fetch."

    if pulled.returncode == 0:
        return "Image pulled successfully."

    stderr_output = pulled.stderr.strip()
    stdout_output = pulled.stdout.strip()
    details = "\n".join(filter(None, [stdout_output, stderr_output]))
    return f"Image pull failed (continuing with tool fetch): {details or 'unknown error'}"


def _run_command(command: List[str], extra_env: Dict[str, str] | None = None) -> Tuple[bool, str]:
    """Execute the CLI tool, stream stderr to logs, and return (success, output_or_error)."""
    timeout = int(os.environ.get("SBOM_GENERATION_TIMEOUT", "600"))
    command_preview = " ".join(shlex.quote(token) for token in command)
    app.logger.info("SBOM command start: %s", command_preview)

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_build_env(**(extra_env or {})),
        )
    except FileNotFoundError:
        return False, (
            "The requested SBOM tool is not installed inside the container. "
            "If you are developing locally, please install both Syft and Trivy, "
            "or build/run the provided Docker image."
        )
    except OSError as exc:
        return False, f"Failed to start SBOM tool: {exc}"

    stderr_lines: List[str] = []

    def _stream_stderr(pipe):
        for line in iter(pipe.readline, ""):
            striped = line.rstrip()
            if striped:
                app.logger.info("[sbom-progress] %s", striped)
                stderr_lines.append(striped)

    stderr_thread = threading.Thread(target=_stream_stderr, args=(process.stderr,), daemon=True)
    stderr_thread.start()

    try:
        stdout_data, stderr_data = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        return False, "SBOM generation timed out. Try a smaller image or increase the timeout."
    finally:
        stderr_thread.join(timeout=1)

    if stderr_data:
        for line in stderr_data.splitlines():
            striped = line.strip()
            if striped:
                app.logger.info("[sbom-progress] %s", striped)
                stderr_lines.append(striped)

    rc = process.returncode
    if rc != 0:
        details = "\n".join(filter(None, [stdout_data.strip(), "\n".join(stderr_lines)]))
        snippet = (details or "").strip()
        if len(snippet) > 1200:
            snippet = snippet[:1200] + "...(truncated)"
        app.logger.error("SBOM command failed (rc=%s): %s | stderr/summary: %s", rc, command_preview, snippet)
        return False, details or "SBOM tool failed without providing output."

    app.logger.info("SBOM command finished (rc=%s)", rc)
    return True, stdout_data


def _generate_bulk_sboms(
    image_entries: List[Dict[str, Any]], registry_username: str = "", registry_password: str = ""
) -> Dict[str, Any]:
    """Generate SBOMs for multiple images (Syft/Trivy x SPDX/CycloneDX) and bundle them as a ZIP."""
    combinations = [(tool, sbom_format) for tool in SUPPORTED_TOOLS for sbom_format in SUPPORTED_FORMATS]
    results: List[Dict[str, Any]] = []
    zip_buffer = io.BytesIO()
    had_failure = False
    auth_kwargs = {"registry_username": registry_username, "registry_password": registry_password}

    with zipfile.ZipFile(zip_buffer, mode="w", compression=ZIP_COMPRESSION) as zip_file:
        for entry in image_entries:
            image_ref = entry["image_ref"]
            folder = _safe_image_folder(image_ref)
            prefetch_note = _ensure_image_cached(image_ref, {"registry_username": registry_username, "registry_password": registry_password})
            app.logger.info("Prefetch result for %s: %s", image_ref, prefetch_note)
            entry["prefetch"] = prefetch_note

            for tool, sbom_format in combinations:
                command = _build_command(tool, image_ref, sbom_format)
                command_preview = " ".join(shlex.quote(token) for token in command)
                success, output_or_error = _run_command(command, extra_env=auth_kwargs)
                record: Dict[str, Any] = {
                    "image_ref": image_ref,
                    "tool": tool,
                    "format": sbom_format,
                    "command": command_preview,
                    "success": success,
                }

                if success:
                    filename = _build_filename(image_ref, tool, sbom_format)
                    zip_file.writestr(f"{folder}/{filename}", output_or_error)
                    saved_path = _write_sbom_to_disk(output_or_error, filename)
                    record.update({"filename": filename, "saved_path": saved_path})
                    app.logger.info("SBOM success [%s %s %s] -> %s", image_ref, tool, sbom_format, filename)
                else:
                    had_failure = True
                    friendly = _friendly_error(output_or_error)
                    record["error"] = friendly
                    app.logger.warning("SBOM failure [%s %s %s]: %s", image_ref, tool, sbom_format, friendly)
                    zip_file.writestr(f"errors/{folder}-{tool}-{sbom_format}.txt", friendly)

                results.append(record)

            entry["cleanup_message"] = _cleanup_image(image_ref)

    zip_buffer.seek(0)
    zip_bytes = zip_buffer.getvalue()
    zip_filename = f"sboms-batch-{uuid.uuid4().hex}.zip"
    zip_token = _cache_download(zip_bytes, zip_filename, mimetype="application/zip")
    zip_saved_path = _write_bytes_to_disk(zip_bytes, zip_filename)

    return {
        "success": True,
        "all_succeeded": not had_failure,
        "had_failures": had_failure,
        "zip_token": zip_token,
        "zip_filename": zip_filename,
        "zip_saved_path": zip_saved_path,
        "records": results,
    }


@app.route("/api/sbom/all", methods=["POST"])
def api_sbom_all():
    """Generate SBOMs for all tool/format combinations for a single image and bundle them as ZIP."""
    payload = request.get_json(silent=True) or {}
    image_ref = (payload.get("image_ref") or "").strip()
    registry_username = payload.get("registry_username") or ""
    registry_password = payload.get("registry_password") or ""

    if not image_ref:
        return jsonify({"success": False, "error": "Docker image reference is required (example: nginx:latest)."}), 400

    try:
        entry = _prepare_single_entry(image_ref)
    except Exception as exc:  # noqa: BLE001 - return friendly message
        return jsonify({"success": False, "error": str(exc)}), 400

    bulk_result = _generate_bulk_sboms([entry], registry_username=registry_username, registry_password=registry_password)
    had_failures = bulk_result.get("had_failures", False)
    status_code = 200

    return (
        jsonify(
            {
                "success": True,
                "all_succeeded": not had_failures,
                "had_failures": had_failures,
                "image_ref": image_ref,
                "records": bulk_result["records"],
                "zip_download_token": bulk_result["zip_token"],
                "zip_filename": bulk_result["zip_filename"],
                "zip_saved_path": bulk_result["zip_saved_path"],
            }
        ),
        status_code,
    )


@app.route("/api/sbom", methods=["POST"])
def api_sbom():
    payload = request.get_json(silent=True) or {}
    image_ref = (payload.get("image_ref") or "").strip()
    selected_tool = payload.get("tool") or "syft"
    selected_format = payload.get("format") or "spdx"

    if not image_ref:
        return jsonify({"success": False, "error": "Docker image reference is required (example: nginx:latest)."}), 400
    if selected_tool not in SUPPORTED_TOOLS:
        return jsonify({"success": False, "error": "Invalid SBOM tool selection."}), 400
    if selected_format not in SUPPORTED_FORMATS:
        return jsonify({"success": False, "error": "Invalid SBOM format selection."}), 400

    command = _build_command(selected_tool, image_ref, selected_format)
    command_preview = " ".join(shlex.quote(token) for token in command)
    registry_username = payload.get("registry_username") or ""
    registry_password = payload.get("registry_password") or ""
    env_kwargs = {"registry_username": registry_username, "registry_password": registry_password}

    success, output_or_error = _run_command(command, extra_env=env_kwargs)
    if not success:
        return jsonify({"success": False, "error": _friendly_error(output_or_error), "command": command_preview}), 500

    sbom_output = output_or_error
    download_filename = _build_filename(image_ref, selected_tool, selected_format)
    download_token = _cache_download(sbom_output, download_filename)
    saved_path = _write_sbom_to_disk(sbom_output, download_filename)
    app.logger.info("SBOM generated for %s using %s (%s). Saved to %s", image_ref, selected_tool, selected_format, saved_path)

    cleanup_message = _cleanup_image(image_ref)

    return jsonify(
        {
            "success": True,
            "command": command_preview,
            "sbom": sbom_output,
            "download_token": download_token,
            "download_filename": download_filename,
            "saved_path": saved_path,
            "cleanup_message": cleanup_message,
        }
    )


@app.route("/api/download/<token>", methods=["GET"])
def download(token: str):
    sbom_entry = DOWNLOAD_CACHE.get(token)
    if not sbom_entry:
        abort(404)

    content = None
    filename = "download"
    mimetype = "application/json"

    if isinstance(sbom_entry, tuple):
        if len(sbom_entry) == 2:
            content, filename = sbom_entry
        elif len(sbom_entry) >= 3:
            content, filename, mimetype = sbom_entry[:3]

    if content is None:
        abort(404)

    payload_bytes = content if isinstance(content, (bytes, bytearray)) else str(content).encode("utf-8")
    payload = io.BytesIO(payload_bytes)
    payload.seek(0)
    return send_file(
        payload,
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype,
    )


# User-friendly error messages (overrides any earlier definition).
def _friendly_error(raw: str) -> str:
    """Return a shorter, user-friendly error message."""
    text = (raw or "").lower()
    if "authentication required" in text or "could not determine source" in text or "manifest unknown" in text:
        return "指定された Docker イメージが見つからないか、プライベートのためアクセスできません。イメージ名と認証情報を確認してください。"
    if "docker daemon" in text or "connect to docker daemon" in text:
        return "Docker デーモンに接続できません。Docker が起動しているか確認してください。"
    if "timeout" in text:
        return "処理がタイムアウトしました。イメージサイズやネットワーク状況を確認してください。"
    return raw


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "tools": list(SUPPORTED_TOOLS.keys()), "formats": list(SUPPORTED_FORMATS.keys())})


@app.errorhandler(404)
def handle_404(_error):
    return jsonify({"success": False, "error": "Not found"}), 404


@app.errorhandler(500)
def handle_500(error):
    # Log the underlying error and return JSON to avoid HTML responses.
    app.logger.error("Unhandled server error: %s", error, exc_info=error)
    return jsonify({"success": False, "error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), debug=True)
