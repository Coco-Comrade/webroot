"""
HTTP Server
Author: Omer Attia
Date: 1/1/2026
"""
from __future__ import annotations

import atexit
import logging
import os
import socket
from typing import Any
from urllib.parse import parse_qs, urlsplit

QUEUE_SIZE: int = 10
IP: str = "0.0.0.0"
PORT: int = 80  # change to 8080 if permission error
SOCKET_TIMEOUT: int = 10

BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
ROOT_WEB: str = BASE_DIR
UPLOAD_DIR: str = os.path.join(BASE_DIR, "upload")

DEFAULT_URL: str = "/"
FORBIDDEN_URI: str = "/forbidden"
ERROR_URI: str = "/error"
MOVED_URI: str = "/moved"

CALC_NEXT_URI: str = "/calculate-next"
CALC_AREA_URI: str = "/calculate-area"
UPLOAD_URI: str = "/upload"
IMAGE_URI: str = "/image"

REDIRECTION_DICTIONARY: dict[str, str] = {
    MOVED_URI: "/",
}

CONTENT_TYPES: dict[str, str] = {
    "html": "text/html; charset=utf-8",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "css": "text/css",
    "js": "text/javascript; charset=UTF-8",
    "ico": "image/x-icon",
    "txt": "text/plain; charset=utf-8",
    "gif": "image/gif",
}

LOG_PATH: str = os.path.join(BASE_DIR, "server.log")

root = logging.getLogger()
root.setLevel(logging.INFO)

for handler in root.handlers[:]:
    root.removeHandler(handler)

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

file_handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

root.addHandler(file_handler)
root.addHandler(console_handler)

atexit.register(logging.shutdown)

log = logging.getLogger()
log.info("Logging initialized (INFO and above). Log file: %s", LOG_PATH)


def get_file_data(file_name: str) -> bytes:
    """
    Param: file_name – the name of the file that should be read from the server.
    This function opens the requested file in binary mode and reads its full
    content.
    Return: the file’s data as bytes, so it can be sent directly to the client.

    :param file_name: Path to the file.
    :return: File bytes.
    """
    with open(file_name, "rb") as file:
        return file.read()


def build_response(
    status_line: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> bytes:
    """Build HTTP response bytes.

    :param status_line: HTTP status line.
    :param headers: Dictionary of headers.
    :param body: Body bytes.
    :return: Full response bytes.
    """
    if headers is None:
        headers = {}

    headers["Content-Length"] = str(len(body))
    headers["Connection"] = "close"

    response = status_line + "\r\n"
    for key, value in headers.items():
        response += f"{key}: {value}\r\n"
    response += "\r\n"
    return response.encode("utf-8") + body


def error_page(code: int, msg: str) -> bytes:
    """
    Builds an HTML error page.

    :param code: HTTP status code.
    :param msg: Status message.
    :return: HTML bytes.
    """
    html = (
        "<!doctype html>"
        "<html><head><meta charset='utf-8'>"
        f"<title>{code} {msg}</title></head>"
        f"<body><h1>{code} {msg}</h1></body></html>"
    )
    return html.encode("utf-8")


def _safe_filename(name: str | None) -> str:
    """
    Cleans and validates a filename received from the client.

    This function prevents path traversal attacks by ensuring that
    the filename does not contain directory separators or parent
    directory references.

    :param name: The filename provided by the client (string).
    :return: A safe filename string, or an empty string if invalid.
    """
    if name is None:
        return ""

    cleaned = name.strip().replace("\\", "/")
    base = os.path.basename(cleaned)

    if base in ("", ".", ".."):
        return ""
    if "/" in base or "\\" in base or ".." in base:
        return ""
    return base


def parse_http_request(
    request_bytes: bytes,
) -> tuple[str, str, dict[str, str], str, dict[str, str], bytes]:
    """
    Parses a raw HTTP request into its components.

    This function extracts the HTTP method, requested path, query
    parameters, HTTP version, headers, and request body.
    It is required to support query strings and POST requests.

    :param request_bytes: The raw HTTP request received from the socket.
    :return: A tuple containing:
             (method, path, query_dict, http_version, headers_dict, body_bytes)
    """
    header_end = request_bytes.find(b"\r\n\r\n")
    if header_end == -1:
        raise ValueError("No header terminator found")

    header_part = request_bytes[:header_end].decode("utf-8", errors="replace")
    body_part = request_bytes[header_end + 4 :]

    lines = header_part.split("\r\n")
    if not lines or len(lines[0].split(" ")) != 3:
        raise ValueError("Bad request line")

    method, target, version = lines[0].split(" ", 2)
    method = method.strip()
    target = target.strip()
    version = version.strip()

    if not target.startswith("/"):
        raise ValueError("Target must start with /")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("Bad header line")
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    url = urlsplit(target)
    path_only = url.path if url.path else "/"

    query_raw = parse_qs(url.query, keep_blank_values=True)
    query = {key: (value[0] if value else "") for key, value in query_raw.items()}

    return method, path_only, query, version, headers, body_part


def read_full_request(
    client_socket: socket.socket,
    max_header_bytes: int = 64 * 1024,
    max_body_bytes: int = 20 * 1024 * 1024,
) -> tuple[str, str, dict[str, str], str, dict[str, str], bytes]:
    """
    Reads the complete HTTP request from the client socket.

    This function first reads the HTTP headers and then reads the
    request body based on the Content-Length header.
    It ensures that POST requests (such as file uploads) are read fully.

    :param client_socket: The socket connected to the client.
    :param max_header_bytes: Safety limit for headers size.
    :param max_body_bytes: Safety limit for body size.
    :return: A tuple containing:
             (method, path, query_dict, http_version, headers_dict, body_bytes)
    """
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = client_socket.recv(4096)
        except (socket.timeout, TimeoutError) as exc:
            raise TimeoutError from exc

        if not chunk:
            break

        data += chunk
        if len(data) > max_header_bytes:
            raise ValueError("Headers too large")

    if b"\r\n\r\n" not in data:
        raise ValueError("Incomplete headers")

    method, path_only, query, version, headers, body_part = parse_http_request(data)

    content_length = 0
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"])
        except ValueError as exc:
            raise ValueError("Bad Content-Length") from exc

        if content_length < 0 or content_length > max_body_bytes:
            raise ValueError("Body too large or invalid length")

    remaining = content_length - len(body_part)
    while remaining > 0:
        try:
            chunk = client_socket.recv(min(4096, remaining))
        except (socket.timeout, TimeoutError) as exc:
            raise TimeoutError from exc

        if not chunk:
            break

        body_part += chunk
        remaining -= len(chunk)

    return method, path_only, query, version, headers, body_part


def validate_http_request(method: str, version: str, path_only: str) -> bool:
    """
    Param: request – the raw HTTP request string received from the client.
    This function checks that the request is correctly formatted, uses the GET
    method, and follows the HTTP/1.1 protocol.
    Return: a tuple containing True/False (request validity) and the requested
    URL.

    :param method: HTTP method.
    :param version: HTTP version.
    :param path_only: Request path.
    :return: True if valid, False otherwise.
    """
    if method not in ("GET", "POST") or version != "HTTP/1.1":
        return False
    if not path_only.startswith("/"):
        return False
    return True


def _send_400(client_socket: socket.socket, msg: str = "Bad Request") -> None:
    body = f"<html><body><h1>400 {msg}</h1></body></html>".encode("utf-8")
    client_socket.send(
        build_response(
            "HTTP/1.1 400 Bad Request",
            {"Content-Type": "text/html; charset=utf-8"},
            body,
        )
    )


def _send_404(client_socket: socket.socket) -> None:
    body = error_page(404, "Not Found")
    client_socket.send(
        build_response(
            "HTTP/1.1 404 Not Found",
            {"Content-Type": "text/html; charset=utf-8"},
            body,
        )
    )


def _send_405(client_socket: socket.socket, allow: str) -> None:
    body = error_page(405, "Method Not Allowed")
    client_socket.send(
        build_response(
            "HTTP/1.1 405 Method Not Allowed",
            {"Content-Type": "text/html; charset=utf-8", "Allow": allow},
            body,
        )
    )


def handle_service_endpoints(
    method: str,
    path_only: str,
    query: dict[str, str],
    headers: dict[str, str],
    body: bytes,
    client_socket: socket.socket,
) -> bool:
    """
    Handles the service endpoints required by the exercise.

    Supported endpoints:
    - GET  /calculate-next
    - GET  /calculate-area
    - POST /upload
    - GET  /image

    Each endpoint processes the request and sends the appropriate
    HTTP response directly to the client.

    :param method: The HTTP method (GET or POST).
    :param path_only: The requested URL path (without query string).
    :param query: Dictionary of query parameters.
    :param headers: Dictionary of HTTP request headers.
    :param body: The request body as bytes.
    :param client_socket: The socket connected to the client.
    :return: True if the request was handled, False otherwise.
    """
    _ = headers  # kept for signature completeness (not used currently)

    if path_only == CALC_NEXT_URI:
        if method != "GET":
            _send_405(client_socket, "GET")
            return True

        if "num" not in query:
            _send_400(client_socket, "Missing num")
            return True

        try:
            n = int(query["num"])
        except ValueError:
            _send_400(client_socket, "num must be an integer")
            return True

        out = str(n + 1).encode("utf-8")
        client_socket.send(
            build_response(
                "HTTP/1.1 200 OK",
                {"Content-Type": "text/plain; charset=utf-8"},
                out,
            )
        )
        return True

    if path_only == CALC_AREA_URI:
        if method != "GET":
            _send_405(client_socket, "GET")
            return True

        if "height" not in query or "width" not in query:
            _send_400(client_socket, "Missing height/width")
            return True

        try:
            h = float(query["height"])
            w = float(query["width"])
        except ValueError:
            _send_400(client_socket, "height/width must be numbers")
            return True

        area = 0.5 * h * w
        out = str(area).encode("utf-8")
        client_socket.send(
            build_response(
                "HTTP/1.1 200 OK",
                {"Content-Type": "text/plain; charset=utf-8"},
                out,
            )
        )
        return True

    if path_only == UPLOAD_URI:
        if method != "POST":
            _send_405(client_socket, "POST")
            return True

        filename = query.get("file-name") or query.get("name-file") or ""
        filename = _safe_filename(filename)
        if not filename:
            _send_400(client_socket, "Missing/invalid file-name")
            return True

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        save_path = os.path.join(UPLOAD_DIR, filename)

        try:
            with open(save_path, "wb") as file:
                file.write(body)
        except OSError as exc:
            log.error("Failed saving upload: %s", exc)
            body_err = error_page(500, "Internal Server Error")
            client_socket.send(
                build_response(
                    "HTTP/1.1 500 Internal Server Error",
                    {"Content-Type": "text/html; charset=utf-8"},
                    body_err,
                )
            )
            return True

        client_socket.send(
            build_response(
                "HTTP/1.1 200 OK",
                {"Content-Type": "text/plain; charset=utf-8"},
                b"OK",
            )
        )
        return True

    if path_only == IMAGE_URI:
        if method != "GET":
            _send_405(client_socket, "GET")
            return True

        img_name = query.get("image-name") or query.get("name-image") or ""
        img_name = _safe_filename(img_name)
        if not img_name:
            _send_400(client_socket, "Missing/invalid image-name")
            return True

        img_path = os.path.join(UPLOAD_DIR, img_name)
        if not os.path.isfile(img_path):
            _send_404(client_socket)
            return True

        _, ext = os.path.splitext(img_path)
        file_type = ext.lower().lstrip(".")
        content_type = CONTENT_TYPES.get(file_type, "application/octet-stream")

        data = get_file_data(img_path)
        client_socket.send(
            build_response(
                "HTTP/1.1 200 OK",
                {"Content-Type": content_type},
                data,
            )
        )
        return True

    return False


def handle_client_request(resource: str, client_socket: socket.socket) -> None:
    """
    Param: resource – the requested URL, client_socket – the socket connected to
    the client.
    This function decides which HTTP response should be sent based on the
    requested resource, including errors, redirects, or a successful file
    response.
    Return: None. The response is sent directly to the client through the
    socket.

    :param resource: Raw requested resource string.
    :param client_socket: Client socket.
    :return: None.
    """
    if resource == "":
        resource = DEFAULT_URL

    path_only = resource.split("?", 1)[0]

    if path_only == FORBIDDEN_URI:
        body = error_page(403, "Forbidden")
        client_socket.send(
            build_response(
                "HTTP/1.1 403 Forbidden",
                {"Content-Type": "text/html; charset=utf-8"},
                body,
            )
        )
        return

    if path_only == ERROR_URI:
        body = error_page(500, "Internal Server Error")
        client_socket.send(
            build_response(
                "HTTP/1.1 500 Internal Server Error",
                {"Content-Type": "text/html; charset=utf-8"},
                body,
            )
        )
        return

    if path_only in REDIRECTION_DICTIONARY:
        client_socket.send(
            build_response(
                "HTTP/1.1 302 Found",
                {"Location": REDIRECTION_DICTIONARY[path_only]},
                b"",
            )
        )
        return

    if path_only == "/":
        rel_path = "index.html"
    else:
        rel_path = path_only.lstrip("/")

    normalized = os.path.normpath(rel_path)
    full_path = os.path.join(ROOT_WEB, normalized)

    root_abs = os.path.abspath(ROOT_WEB)
    full_abs = os.path.abspath(full_path)
    if not (full_abs == root_abs or full_abs.startswith(root_abs + os.sep)):
        body = error_page(403, "Forbidden")
        client_socket.send(
            build_response(
                "HTTP/1.1 403 Forbidden",
                {"Content-Type": "text/html; charset=utf-8"},
                body,
            )
        )
        return

    if not os.path.isfile(full_path):
        body = error_page(404, "Not Found")
        client_socket.send(
            build_response(
                "HTTP/1.1 404 Not Found",
                {"Content-Type": "text/html; charset=utf-8"},
                body,
            )
        )
        return

    _, ext = os.path.splitext(full_path)
    file_type = ext.lower().lstrip(".")
    content_type = CONTENT_TYPES.get(file_type, "application/octet-stream")

    data = get_file_data(full_path)
    client_socket.send(
        build_response(
            "HTTP/1.1 200 OK",
            {"Content-Type": content_type},
            data,
        )
    )


def _asserts_for_server() -> None:
    assert os.path.isdir(ROOT_WEB), "ROOT_WEB directory does not exist"
    assert os.path.isfile(os.path.join(ROOT_WEB, "index.html")), (
        "index.html not found in ROOT_WEB"
    )

    assert "html" in CONTENT_TYPES, "HTML content-type missing"
    assert "jpg" in CONTENT_TYPES, "JPG content-type missing"
    assert MOVED_URI in REDIRECTION_DICTIONARY, "Missing /moved redirection"

    req = b"GET /calculate-next?num=8 HTTP/1.1\r\nHost: x\r\n\r\n"
    method, path, query, version, headers, body = parse_http_request(req)
    assert method == "GET" and path == "/calculate-next"
    assert query.get("num") == "8" and version == "HTTP/1.1"

    req2 = (
        b"POST /upload?file-name=a.txt HTTP/1.1\r\n"
        b"Host: x\r\nContent-Length: 3\r\n\r\nabc"
    )
    method2, path2, query2, version2, headers2, body2 = parse_http_request(req2)
    assert method2 == "POST" and path2 == "/upload"
    assert query2.get("file-name") == "a.txt" and body2 == b"abc"

    assert validate_http_request("GET", "HTTP/1.1", "/")
    assert validate_http_request("POST", "HTTP/1.1", "/upload")
    assert not validate_http_request("PUT", "HTTP/1.1", "/")
    assert not validate_http_request("GET", "HTTP/1.0", "/")


def handle_client(client_socket: socket.socket) -> None:
    log.info("handle_client started")
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        try:
            method, path_only, query, version, headers, body = read_full_request(
                client_socket
            )
        except TimeoutError:
            log.warning("Socket timeout in handle_client")
            return
        except socket.timeout:
            log.warning("Socket timeout in handle_client")
            return

        log.info(
            "Request: %s %s %s query=%s",
            method,
            path_only,
            version,
            query,
        )

        if not validate_http_request(method, version, path_only):
            log.warning("400 Bad Request (invalid HTTP request)")
            _send_400(client_socket)
            return

        if handle_service_endpoints(
            method,
            path_only,
            query,
            headers,
            body,
            client_socket,
        ):
            return

        if method != "GET":
            _send_405(client_socket, "GET")
            return

        handle_client_request(path_only, client_socket)

    except ValueError as exc:
        log.warning("Bad request: %s", exc)
        _send_400(client_socket)
    except Exception as exc:
        log.error("Exception in handle_client: %s", exc)
        body_err = error_page(500, "Internal Server Error")
        client_socket.send(
            build_response(
                "HTTP/1.1 500 Internal Server Error",
                {"Content-Type": "text/html; charset=utf-8"},
                body_err,
            )
        )


def main() -> None:
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    _asserts_for_server()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((IP, PORT))
    server_socket.listen(QUEUE_SIZE)

    print("Serving from:", os.path.abspath(ROOT_WEB))
    print("Upload dir:", os.path.abspath(UPLOAD_DIR))
    print("Index exists:", os.path.isfile(os.path.join(ROOT_WEB, "index.html")))
    print("Listening on port", PORT)

    while True:
        client_socket, _addr = server_socket.accept()
        try:
            handle_client(client_socket)
        finally:
            client_socket.close()


if __name__ == "__main__":
    main()
