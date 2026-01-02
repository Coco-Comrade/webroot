import os
import socket

QUEUE_SIZE = 10
IP = '0.0.0.0'
PORT = 80          # change to 8080 if permission error
SOCKET_TIMEOUT = 2

# Serve files from the same directory as this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_WEB = BASE_DIR

DEFAULT_URL = "/"
FORBIDDEN_URI = "/forbidden"
ERROR_URI = "/error"
MOVED_URI = "/moved"

REDIRECTION_DICTIONARY = {
    MOVED_URI: "/"
}

CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "css": "text/css",
    "js": "text/javascript; charset=UTF-8",
    "ico": "image/x-icon",
    "txt": "text/plain",
    "gif": "image/gif",
}


def get_file_data(file_name):
    """Read file data as bytes."""
    with open(file_name, "rb") as f:
        return f.read()


def build_response(status_line, headers=None, body=b""):
    """Build HTTP response bytes."""
    if headers is None:
        headers = {}

    headers["Content-Length"] = str(len(body))
    headers["Connection"] = "close"

    response = status_line + "\r\n"
    for k, v in headers.items():
        response += f"{k}: {v}\r\n"
    response += "\r\n"
    return response.encode() + body


def error_page(code, msg):
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{code} {msg}</title></head>
<body><h1>{code} {msg}</h1></body></html>"""
    return html.encode("utf-8")


def handle_client_request(resource, client_socket):
    if resource == "":
        resource = DEFAULT_URL

    path_only = resource.split("?", 1)[0]

    if path_only == FORBIDDEN_URI:
        body = error_page(403, "Forbidden")
        client_socket.send(build_response(
            "HTTP/1.1 403 Forbidden",
            {"Content-Type": "text/html; charset=utf-8"},
            body))
        return

    if path_only == ERROR_URI:
        body = error_page(500, "Internal Server Error")
        client_socket.send(build_response(
            "HTTP/1.1 500 Internal Server Error",
            {"Content-Type": "text/html; charset=utf-8"},
            body))
        return

    if path_only in REDIRECTION_DICTIONARY:
        client_socket.send(build_response(
            "HTTP/1.1 302 Found",
            {"Location": REDIRECTION_DICTIONARY[path_only]},
            b""))
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
        client_socket.send(build_response(
            "HTTP/1.1 403 Forbidden",
            {"Content-Type": "text/html; charset=utf-8"},
            body))
        return

    if not os.path.isfile(full_path):
        body = error_page(404, "Not Found")
        client_socket.send(build_response(
            "HTTP/1.1 404 Not Found",
            {"Content-Type": "text/html; charset=utf-8"},
            body))
        return

    _, ext = os.path.splitext(full_path)
    file_type = ext.lower().lstrip(".")
    content_type = CONTENT_TYPES.get(file_type, "application/octet-stream")

    data = get_file_data(full_path)
    client_socket.send(build_response(
        "HTTP/1.1 200 OK",
        {"Content-Type": content_type},
        data))


def validate_http_request(request):
    if request is None or "\r\n" not in request:
        return False, ""

    first_line = request.split("\r\n", 1)[0]
    parts = first_line.split(" ")

    if len(parts) != 3:
        return False, ""

    method, uri, version = parts
    if method != "GET" or version != "HTTP/1.1":
        return False, ""
    if not uri.startswith("/"):
        return False, ""

    return True, uri


# =========================
# ✅ ASSERTS – correctness only
# =========================
def _asserts_for_server():
    assert os.path.isdir(ROOT_WEB), "ROOT_WEB directory does not exist"
    assert os.path.isfile(os.path.join(ROOT_WEB, "index.html")), \
        "index.html not found in ROOT_WEB"

    assert "html" in CONTENT_TYPES, "HTML content-type missing"
    assert "jpg" in CONTENT_TYPES, "JPG content-type missing"
    assert MOVED_URI in REDIRECTION_DICTIONARY, "Missing /moved redirection"

    ok, res = validate_http_request("GET / HTTP/1.1\r\n\r\n")
    assert ok and res == "/", "Valid GET / failed"

    ok, _ = validate_http_request("POST / HTTP/1.1\r\n\r\n")
    assert not ok, "POST request should be invalid"

    ok, _ = validate_http_request("GET / HTTP/1.0\r\n\r\n")
    assert not ok, "HTTP/1.0 should be invalid"

    ok, res = validate_http_request("GET /index.html HTTP/1.1\r\n\r\n")
    assert ok and res == "/index.html", "GET /index.html failed"


def handle_client(client_socket):
    print("Client connected")
    try:
        request_bytes = client_socket.recv(4096)
        if not request_bytes:
            return

        request = request_bytes.decode("utf-8", errors="replace")
        valid_http, resource = validate_http_request(request)

        if valid_http:
            handle_client_request(resource, client_socket)
        else:
            body = error_page(400, "Bad Request")
            client_socket.send(build_response(
                "HTTP/1.1 400 Bad Request",
                {"Content-Type": "text/html; charset=utf-8"},
                body))
    finally:
        print("Closing connection")


def main():
    # ✅ run correctness checks once
    _asserts_for_server()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((IP, PORT))
    server_socket.listen(QUEUE_SIZE)

    print("Serving from:", os.path.abspath(ROOT_WEB))
    print("Index exists:", os.path.isfile(os.path.join(ROOT_WEB, "index.html")))
    print("Listening on port", PORT)

    while True:
        client_socket, addr = server_socket.accept()
        try:
            handle_client(client_socket)
        finally:
            client_socket.close()


if __name__ == "__main__":
    main()
