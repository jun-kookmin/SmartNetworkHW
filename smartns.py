import os
import sys
import socket
import struct
import threading
import subprocess
import time
import queue
import json
from dataclasses import dataclass
from typing import Optional, Tuple, List

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

try:
    import requests
except Exception:
    requests = None


# ----------------- 공용/유틸 -----------------

def is_windows() -> bool:
    return os.name == "nt"

def run_cmd(cmd: List[str], timeout: float = 5.0) -> str:
    """OS 명령 실행. 에러도 stdout로 회수."""
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        out = (p.stdout or "") + (p.stderr or "")
        return out.strip()
    except Exception as e:
        return f"[cmd error] {e}"

def safe_int(s: str, default: int = 0) -> int:
    try:
        return int(s)
    except Exception:
        return default

def pad_fixed(data: bytes, n: int) -> bytes:
    """FIXED 전송용 정확히 n바이트로 맞춤."""
    if len(data) > n:
        return data[:n]
    return data + b'\x00' * (n - len(data))

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """정확히 n바이트 수신(고정 길이)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def recv_until_newline(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    """\\n까지 수신(가변 길이)."""
    buf = b""
    while True:
        b1 = sock.recv(1)
        if not b1:
            raise ConnectionError("socket closed")
        buf += b1
        if b1 == b"\n":
            break
        if len(buf) > max_bytes:
            raise ValueError("too large message")
    return buf

@dataclass
class ClientConn:
    sock: socket.socket
    addr: Tuple[str, int]
    thread: threading.Thread


# ----------------- GUI App -----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("스마트 네트워크 서비스 — A+ 완성본")
        self.geometry("1100x720")

        self.server_running = False
        self.client_connected = False

        self.server_sock: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.server_stop_event = threading.Event()
        self.server_lock = threading.Lock()
        self.server_clients: List[ClientConn] = []
        self.server_counter = 0

        self.client_sock: Optional[socket.socket] = None
        self.client_recv_thread: Optional[threading.Thread] = None
        self.client_stop_event = threading.Event()
        
        self.draw_send_queue: "queue.Queue[bytes]" = queue.Queue()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.pg_diag = ttk.Frame(nb); nb.add(self.pg_diag, text="네트워크 진단")
        self.pg_server = ttk.Frame(nb); nb.add(self.pg_server, text="TCP 서버")
        self.pg_client = ttk.Frame(nb); nb.add(self.pg_client, text="TCP 클라이언트")
        self.pg_buf = ttk.Frame(nb); nb.add(self.pg_buf, text="버퍼/소켓")
        self.pg_draw = ttk.Frame(nb); nb.add(self.pg_draw, text="네트워크 그림판")
        self.pg_sfc = ttk.Frame(nb); nb.add(self.pg_sfc, text="Ryu SFC")

        self._build_diag()
        self._build_server()
        self._build_client()
        self._build_buf()
        self._build_draw()
        self._build_sfc()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------- 네트워크 진단 ----------------
    def _build_diag(self):
        left = ttk.Frame(self.pg_diag, padding=8); left.pack(side="left", fill="y")
        right = ttk.Frame(self.pg_diag, padding=8); right.pack(side="right", fill="both", expand=True)

        ttk.Label(left, text="IP 구성 / netstat / 포트 검사").pack(anchor="w")
        ttk.Button(left, text="IP 구성 확인", command=self.do_ipconfig).pack(fill="x", pady=2)

        self.var_netstat = tk.StringVar(value="9000")
        row = ttk.Frame(left); row.pack(fill="x", pady=2)
        ttk.Entry(row, textvariable=self.var_netstat, width=10).pack(side="left")
        ttk.Button(row, text="netstat 필터", command=self.do_netstat).pack(side="left", padx=4)

        row2 = ttk.Frame(left); row2.pack(fill="x", pady=(6,2))
        self.var_host = tk.StringVar(value="127.0.0.1")
        self.var_port = tk.StringVar(value="9000")
        ttk.Entry(row2, textvariable=self.var_host, width=14).pack(side="left")
        ttk.Entry(row2, textvariable=self.var_port, width=6).pack(side="left", padx=4)
        ttk.Button(row2, text="포트 오픈 검사", command=self.do_check_port).pack(side="left", padx=4)

        ttk.Separator(left).pack(fill="x", pady=8)
        ttk.Label(left, text="바이트/주소 변환").pack(anchor="w")
        ttk.Button(left, text="hton/ntoh 데모", command=self.do_hton).pack(fill="x", pady=2)

        self.var_ipv4 = tk.StringVar(value="8.8.8.8")
        self.var_ipv6 = tk.StringVar(value="2001:4860:4860::8888")

        row3 = ttk.Frame(left); row3.pack(fill="x", pady=2)
        ttk.Entry(row3, textvariable=self.var_ipv4, width=18).pack(side="left")
        ttk.Button(row3, text="inet_pton/ntop(IPv4)", command=self.do_inet4).pack(side="left", padx=4)

        row4 = ttk.Frame(left); row4.pack(fill="x", pady=2)
        ttk.Entry(row4, textvariable=self.var_ipv6, width=26).pack(side="left")
        ttk.Button(row4, text="inet_pton/ntop(IPv6)", command=self.do_inet6).pack(side="left", padx=4)

        ttk.Separator(left).pack(fill="x", pady=8)
        ttk.Label(left, text="DNS/이름 변환").pack(anchor="w")
        self.var_dns = tk.StringVar(value="example.com")
        self.var_rev = tk.StringVar(value="8.8.8.8")

        row5 = ttk.Frame(left); row5.pack(fill="x", pady=2)
        ttk.Entry(row5, textvariable=self.var_dns, width=18).pack(side="left")
        ttk.Button(row5, text="DNS 조회", command=self.do_dns).pack(side="left", padx=4)

        row6 = ttk.Frame(left); row6.pack(fill="x", pady=2)
        ttk.Entry(row6, textvariable=self.var_rev, width=18).pack(side="left")
        ttk.Button(row6, text="역방향 조회", command=self.do_reverse).pack(side="left", padx=4)

        self.out_diag = scrolledtext.ScrolledText(right, height=30)
        self.out_diag.pack(fill="both", expand=True)

    def log_diag(self, s): self._append(self.out_diag, s)

    # ifconfig/ipconfig
    def do_ipconfig(self):
        self.log_diag("[IP 구성 확인]")
        if is_windows():
            out = run_cmd(["ipconfig", "/all"], timeout=6)
        else: # mac/linux: ifconfig
            out = run_cmd(["ifconfig"], timeout=6)
            if "not found" in out.lower() or out.strip() == "":
                out = run_cmd(["ip", "a"], timeout=6)
        self.log_diag(out)

    # netstat -a -n -p tcp | findstr/grep <port>
    def do_netstat(self):
        port = self.var_netstat.get().strip()
        self.log_diag(f"[netstat 필터] port={port}")
        if is_windows():
            cmd = ["netstat", "-a", "-n", "-p", "tcp"]
            out = run_cmd(cmd, timeout=5)
            filtered = "\n".join([line for line in out.splitlines() if port in line])
        else:
            cmd = ["netstat", "-anp", "tcp"]
            out = run_cmd(cmd, timeout=5)
            if "illegal" in out.lower() or "not supported" in out.lower():
                out = run_cmd(["netstat", "-an"], timeout=5)
            filtered = "\n".join([line for line in out.splitlines() if port in line])
        self.log_diag(filtered if filtered else "(no match)")

    # 포트 오픈 여부 검사
    def do_check_port(self):
        host = self.var_host.get().strip()
        port = safe_int(self.var_port.get().strip(), 0)
        self.log_diag(f"[포트 오픈 검사] {host}:{port}")
        try:
            with socket.create_connection((host, port), timeout=2.0) as s:
                self.log_diag("OPEN (연결 성공)")
        except Exception as e:
            self.log_diag(f"CLOSED or FILTERED: {e}")

    # 바이트 정렬 / host<->network
    def do_hton(self):
        self.log_diag("[hton/ntoh 데모]")
        x16 = 0x1234
        x32 = 0x12345678
        x64 = 0x1122334455667788

        n16 = socket.htons(x16)
        h16 = socket.ntohs(n16)

        n32 = socket.htonl(x32)
        h32 = socket.ntohl(n32)

        n64 = struct.unpack("!Q", struct.pack("@Q", x64))[0]
        h64 = struct.unpack("@Q", struct.pack("!Q", n64))[0]

        self.log_diag(f"16-bit host={hex(x16)} -> network={hex(n16)} -> host={hex(h16)}")
        self.log_diag(f"32-bit host={hex(x32)} -> network={hex(n32)} -> host={hex(h32)}")
        self.log_diag(f"64-bit host={hex(x64)} -> network={hex(n64)} -> host={hex(h64)}")

    # inet_pton/ntop IPv4
    def do_inet4(self):
        ip = self.var_ipv4.get().strip()
        self.log_diag(f"[inet_pton/ntop IPv4] {ip}")
        try:
            packed = socket.inet_pton(socket.AF_INET, ip)
            self.log_diag(f"packed={packed} len={len(packed)}")
            unpacked = socket.inet_ntop(socket.AF_INET, packed)
            self.log_diag(f"unpacked={unpacked}")
        except Exception as e:
            self.log_diag(f"error: {e}")

    # inet_pton/ntop IPv6
    def do_inet6(self):
        ip = self.var_ipv6.get().strip()
        self.log_diag(f"[inet_pton/ntop IPv6] {ip}")
        try:
            packed = socket.inet_pton(socket.AF_INET6, ip)
            self.log_diag(f"packed={packed} len={len(packed)}")
            unpacked = socket.inet_ntop(socket.AF_INET6, packed)
            self.log_diag(f"unpacked={unpacked}")
        except Exception as e:
            self.log_diag(f"error: {e}")

    # DNS 조회
    def do_dns(self):
        host = self.var_dns.get().strip()
        self.log_diag(f"[DNS 조회] {host}")
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = sorted(set([i[4][0] for i in infos]))
            for a in addrs:
                self.log_diag(f" - {a}")
        except Exception as e:
            self.log_diag(f"error: {e}")

    # 역방향 이름 조회
    def do_reverse(self):
        ip = self.var_rev.get().strip()
        self.log_diag(f"[역방향 조회] {ip}")
        try:
            name, alias, addr = socket.gethostbyaddr(ip)
            self.log_diag(f"name={name}")
            if alias: self.log_diag(f"alias={alias}")
            self.log_diag(f"addr_list={addr}")
        except Exception as e:
            self.log_diag(f"error: {e}")

    # ---------------- TCP 서버 ----------------
    def _build_server(self):
        top = ttk.Frame(self.pg_server, padding=8); top.pack(fill="x")
        self.var_srv_port = tk.StringVar(value="9000")

        ttk.Label(top, text="포트").pack(side="left")
        ttk.Entry(top, textvariable=self.var_srv_port, width=6).pack(side="left", padx=4)

        self.var_broadcast = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="그림판 브로드캐스트", variable=self.var_broadcast).pack(side="left", padx=6)

        ttk.Button(top, text="서버 시작", command=self.server_start).pack(side="left", padx=4)
        ttk.Button(top, text="서버 정지", command=self.server_stop).pack(side="left", padx=4)

        stat = ttk.Frame(self.pg_server, padding=8); stat.pack(fill="x")
        self.lbl_clients = ttk.Label(stat, text="접속: 0"); self.lbl_clients.pack(side="left")
        self.lbl_counter = ttk.Label(stat, text="카운터: 0"); self.lbl_counter.pack(side="left", padx=12)
        ttk.Button(stat, text="상태 갱신", command=self.server_status).pack(side="left")

        self.out_srv = scrolledtext.ScrolledText(self.pg_server, height=28)
        self.out_srv.pack(fill="both", expand=True)

    def log_srv(self, s): self._append(self.out_srv, s)

    # 멀티스레드 서버 + Lock+Event 안전정지
    def server_start(self):
        if self.server_running:
            messagebox.showinfo("서버", "이미 실행 중")
            return

        port = safe_int(self.var_srv_port.get(), 9000)
        self.server_stop_event.clear()

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(20)
            self.server_sock = srv
        except Exception as e:
            messagebox.showerror("서버 시작 실패", str(e))
            return

        self.server_running = True
        self.log_srv(f"[서버] 시작 @ {port}")
        self.server_thread = threading.Thread(target=self._server_accept_loop, daemon=True)
        self.server_thread.start()

        threading.Thread(target=self._server_draw_broadcast_loop, daemon=True).start()

    def _server_accept_loop(self):
        assert self.server_sock is not None
        while not self.server_stop_event.is_set():
            try:
                self.server_sock.settimeout(1.0)
                cli, addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            th = threading.Thread(target=self._server_client_loop, args=(cli, addr), daemon=True)
            conn = ClientConn(sock=cli, addr=addr, thread=th)
            with self.server_lock:
                self.server_clients.append(conn)
            th.start()

            self.log_srv(f"[서버] 접속 {addr} (총 {len(self.server_clients)})")
            self.server_status()

        self.log_srv("[서버] accept 루프 종료")

    def _server_client_loop(self, cli: socket.socket, addr):
        cli.settimeout(1.0)
        try:
            while not self.server_stop_event.is_set():
                try:
                    mode_b = cli.recv(1)
                    if not mode_b:
                        break
                    mode = mode_b.decode(errors="ignore")

                    if mode == "V":
                        data = recv_until_newline(cli)
                        msg = data.decode(errors="ignore").rstrip("\n")
                        self._server_on_message(addr, f"VAR '{msg}'")
                        cli.sendall(b"V" + data)

                    elif mode == "F":
                        data = recv_exact(cli, 32)
                        msg = data.rstrip(b"\x00").decode(errors="ignore")
                        self._server_on_message(addr, f"FIXED '{msg}'")
                        cli.sendall(b"F" + data)

                    elif mode == "M":
                        hdr = recv_exact(cli, 4)
                        n = struct.unpack("!I", hdr)[0]
                        payload = recv_exact(cli, n)
                        msg = payload.decode(errors="ignore")
                        self._server_on_message(addr, f"MIX '{msg}' (len={n})")
                        cli.sendall(b"M" + hdr + payload)

                    elif mode == "D":
                        payload = recv_exact(cli, 16)
                        if self.var_broadcast.get():
                            self.draw_send_queue.put(payload)
                        self._server_on_message(addr, "DRAW event")
                    else:
                        self._server_on_message(addr, f"UNKNOWN mode={mode}")

                except socket.timeout:
                    continue

        except Exception as e:
            self.log_srv(f"[서버] {addr} 오류: {e}")

        finally:
            try:
                cli.close()
            except Exception:
                pass
            with self.server_lock:
                self.server_clients = [c for c in self.server_clients if c.addr != addr]
            self.log_srv(f"[서버] 해제 {addr} (총 {len(self.server_clients)})")
            self.server_status()

    def _server_on_message(self, addr, text):
        # 공유 카운터+Lock
        with self.server_lock:
            self.server_counter += 1
            count = self.server_counter
        self.log_srv(f"[서버][{addr}] {text} | counter={count}")

    def _server_draw_broadcast_loop(self):
        while not self.server_stop_event.is_set():
            try:
                payload = self.draw_send_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            with self.server_lock:
                dead = []
                for c in self.server_clients:
                    try:
                        c.sock.sendall(b"D" + payload)
                    except Exception:
                        dead.append(c.addr)

                if dead:
                    self.server_clients = [c for c in self.server_clients if c.addr not in dead]

    def server_stop(self):
        if not self.server_running:
            return
        self.log_srv("[서버] 정지 요청")
        self.server_stop_event.set()

        # 소켓 닫기
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass

        # 클라 소켓 닫기
        with self.server_lock:
            for c in self.server_clients:
                try:
                    c.sock.close()
                except Exception:
                    pass
            self.server_clients.clear()

        self.server_running = False
        self.server_status()
        self.log_srv("[서버] 정지 완료")

    def server_status(self):
        with self.server_lock:
            n_cli = len(self.server_clients)
            cnt = self.server_counter
        self.lbl_clients.config(text=f"접속: {n_cli}")
        self.lbl_counter.config(text=f"카운터: {cnt}")

    # ---------------- TCP 클라이언트 ----------------
    def _build_client(self):
        top = ttk.Frame(self.pg_client, padding=8); top.pack(fill="x")

        self.var_cli_host = tk.StringVar(value="127.0.0.1")
        self.var_cli_port = tk.StringVar(value="9000")

        ttk.Label(top, text="호스트").pack(side="left")
        ttk.Entry(top, textvariable=self.var_cli_host, width=16).pack(side="left", padx=4)
        ttk.Label(top, text="포트").pack(side="left")
        ttk.Entry(top, textvariable=self.var_cli_port, width=6).pack(side="left", padx=4)

        ttk.Button(top, text="접속", command=self.cli_connect).pack(side="left", padx=4)
        ttk.Button(top, text="해제", command=self.cli_close).pack(side="left", padx=4)

        opt = ttk.Frame(self.pg_client, padding=8); opt.pack(fill="x")
        self.var_mode = tk.StringVar(value="VAR")
        ttk.Radiobutton(opt, text="VAR(\\n)", variable=self.var_mode, value="VAR").pack(side="left")
        ttk.Radiobutton(opt, text="FIXED(32B)", variable=self.var_mode, value="FIXED").pack(side="left", padx=6)
        ttk.Radiobutton(opt, text="MIX(4B len+data)", variable=self.var_mode, value="MIX").pack(side="left", padx=6)

        self.var_after_close = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="전송 후 종료", variable=self.var_after_close).pack(side="left", padx=8)

        msg = ttk.Frame(self.pg_client, padding=8); msg.pack(fill="x")
        self.var_msg = tk.StringVar(value="hello")
        ttk.Entry(msg, textvariable=self.var_msg, width=60).pack(side="left")
        ttk.Button(msg, text="전송", command=self.cli_send).pack(side="left", padx=6)

        self.out_cli = scrolledtext.ScrolledText(self.pg_client, height=28)
        self.out_cli.pack(fill="both", expand=True)

    def log_cli(self, s): self._append(self.out_cli, s)

    # connect, recv 스레드
    def cli_connect(self):
        if self.client_connected:
            return
        host = self.var_cli_host.get().strip()
        port = safe_int(self.var_cli_port.get().strip(), 9000)

        try:
            self.client_sock = socket.create_connection((host, port), timeout=3.0)
            self.client_sock.settimeout(1.0)
        except Exception as e:
            messagebox.showerror("클라 연결 실패", str(e))
            return

        self.client_connected = True
        self.log_cli(f"[클라] 연결 성공 → {host}:{port}")

        self.client_stop_event.clear()
        self.client_recv_thread = threading.Thread(target=self._cli_recv_loop, daemon=True)
        self.client_recv_thread.start()

    def _cli_recv_loop(self):
        assert self.client_sock is not None
        sock = self.client_sock
        try:
            while not self.client_stop_event.is_set():
                try:
                    mode_b = sock.recv(1)
                    if not mode_b:
                        break
                    mode = mode_b.decode(errors="ignore")

                    if mode == "V":
                        data = recv_until_newline(sock)
                        msg = data.decode(errors="ignore").rstrip("\n")
                        self.log_cli(f"[클라][수신 VAR] '{msg}'")

                    elif mode == "F":
                        data = recv_exact(sock, 32)
                        msg = data.rstrip(b"\x00").decode(errors="ignore")
                        self.log_cli(f"[클라][수신 FIXED] '{msg}'")

                    elif mode == "M":
                        hdr = recv_exact(sock, 4)
                        n = struct.unpack("!I", hdr)[0]
                        payload = recv_exact(sock, n)
                        msg = payload.decode(errors="ignore")
                        self.log_cli(f"[클라][수신 MIX] '{msg}' (len={n})")

                    elif mode == "D":
                        payload = recv_exact(sock, 16)
                        x1, y1, x2, y2 = struct.unpack("!IIII", payload)
                        self._draw_remote_line(x1, y1, x2, y2)
                    else:
                        self.log_cli(f"[클라][수신] UNKNOWN mode={mode}")

                except socket.timeout:
                    continue
        except Exception as e:
            self.log_cli(f"[클라] recv 오류: {e}")
        finally:
            self.log_cli("[클라] recv 루프 종료")
            self._cli_cleanup()

    def _cli_cleanup(self):
        if self.client_sock:
            try:
                self.client_sock.close()
            except Exception:
                pass
        self.client_sock = None
        self.client_connected = False

    def cli_close(self):
        if not self.client_connected:
            return
        self.log_cli("[클라] 연결 해제 요청")
        self.client_stop_event.set()
        try:
            if self.client_sock:
                self.client_sock.close()
        except Exception:
            pass
        self.client_connected = False

    # 전송후종료
    def cli_send(self):
        if not self.client_connected or not self.client_sock:
            messagebox.showinfo("클라", "먼저 접속하세요")
            return

        mode = self.var_mode.get()
        msg = self.var_msg.get()
        data = msg.encode()

        try:
            if mode == "VAR":
                payload = data + b"\n"
                self.client_sock.sendall(b"V" + payload)
                self.log_cli(f"[클라][송신 VAR] '{msg}'")

            elif mode == "FIXED":
                payload = pad_fixed(data, 32)
                self.client_sock.sendall(b"F" + payload)
                self.log_cli(f"[클라][송신 FIXED] '{msg}' (padded to 32B)")

            elif mode == "MIX":
                hdr = struct.pack("!I", len(data))
                self.client_sock.sendall(b"M" + hdr + data)
                self.log_cli(f"[클라][송신 MIX] '{msg}' len={len(data)}")

            else:
                self.log_cli(f"[클라] unknown mode: {mode}")

            if self.var_after_close.get():
                self.log_cli("[클라] 전송 후 종료 체크 → close")
                self.cli_close()

        except Exception as e:
            self.log_cli(f"[클라] send 오류: {e}")
            self.cli_close()

    # ---------------- 버퍼/소켓 ----------------
    def _build_buf(self):
        top = ttk.Frame(self.pg_buf, padding=8); top.pack(fill="x")
        ttk.Button(top, text="클라 소켓 버퍼 조회", command=self.buf_client).pack(side="left", padx=4)
        ttk.Button(top, text="임시 소켓 버퍼 조회", command=self.buf_temp).pack(side="left", padx=4)

        self.out_buf = scrolledtext.ScrolledText(self.pg_buf, height=30)
        self.out_buf.pack(fill="both", expand=True)

    def log_buf(self, s): self._append(self.out_buf, s)

    # 클라 소켓 버퍼 상태 표시
    def buf_client(self):
        self.log_buf("[버퍼] 클라이언트 소켓 버퍼 조회")
        if not self.client_sock:
            self.log_buf("클라 소켓 없음 (먼저 접속)")
            return
        try:
            snd = self.client_sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            rcv = self.client_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log_buf(f"SO_SNDBUF={snd} bytes")
            self.log_buf(f"SO_RCVBUF={rcv} bytes")
        except Exception as e:
            self.log_buf(f"error: {e}")

    # 소켓 버퍼 보기
    def buf_temp(self):
        self.log_buf("[버퍼] 임시 소켓 생성 후 버퍼 조회")
        try:
            tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            snd = tmp.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            rcv = tmp.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            tmp.close()
            self.log_buf(f"SO_SNDBUF={snd} bytes")
            self.log_buf(f"SO_RCVBUF={rcv} bytes")
        except Exception as e:
            self.log_buf(f"error: {e}")

    # ---------------- 네트워크 그림판 ----------------
    def _build_draw(self):
        info = ttk.Frame(self.pg_draw, padding=8); info.pack(fill="x")
        ttk.Label(info, text="그림판 — 드래그 시 선, 서버가 브로드캐스트").pack(side="left")

        self.canvas = tk.Canvas(self.pg_draw, bg="white", height=520)
        self.canvas.pack(fill="both", expand=True, padx=8, pady=8)

        self.canvas.bind("<ButtonPress-1>", self._draw_start)
        self.canvas.bind("<B1-Motion>", self._draw_move)
        self._last_xy = None

    # 드로잉
    def _draw_start(self, e):
        self._last_xy = (e.x, e.y)

    def _draw_move(self, e):
        if not self._last_xy: 
            return
        x1, y1 = self._last_xy
        x2, y2 = e.x, e.y
        self.canvas.create_line(x1, y1, x2, y2)

        # 네트워크 동기화
        if self.client_connected and self.client_sock:
            try:
                payload = struct.pack("!IIII", x1, y1, x2, y2)
                self.client_sock.sendall(b"D" + payload)
            except Exception:
                pass

        self._last_xy = (x2, y2)

    # 원격 드로잉(수신)
    def _draw_remote_line(self, x1, y1, x2, y2):
        def draw():
            self.canvas.create_line(x1, y1, x2, y2)
        self.after(0, draw)

    # ---------------- Ryu SFC (REST) ----------------
    def _build_sfc(self):
        top = ttk.Frame(self.pg_sfc, padding=8); top.pack(fill="x")

        self.var_rest_host = tk.StringVar(value="127.0.0.1")
        self.var_rest_port = tk.StringVar(value="8080")
        self.var_dpid = tk.StringVar(value="1")
        self.var_prio = tk.StringVar(value="100")
        self.var_h1 = tk.StringVar(value="1")
        self.var_fw = tk.StringVar(value="2")
        self.var_nat = tk.StringVar(value="3")
        self.var_h2 = tk.StringVar(value="4")

        ttk.Label(top, text="Ryu").grid(row=0, column=0, sticky="e")
        ttk.Entry(top, textvariable=self.var_rest_host, width=14).grid(row=0, column=1)
        ttk.Label(top, text=":").grid(row=0, column=2)
        ttk.Entry(top, textvariable=self.var_rest_port, width=6).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="DPID").grid(row=0, column=4, sticky="e")
        ttk.Entry(top, textvariable=self.var_dpid, width=6).grid(row=0, column=5)

        ttk.Label(top, text="prio").grid(row=0, column=6, sticky="e")
        ttk.Entry(top, textvariable=self.var_prio, width=6).grid(row=0, column=7)

        ports = ttk.Frame(self.pg_sfc, padding=8); ports.pack(fill="x")
        for i,(lab,var) in enumerate([("h1",self.var_h1),("fw",self.var_fw),("nat",self.var_nat),("h2",self.var_h2)]):
            ttk.Label(ports, text=lab).grid(row=0, column=i*2)
            ttk.Entry(ports, textvariable=var, width=6).grid(row=0, column=i*2+1, padx=4)

        btns = ttk.Frame(self.pg_sfc, padding=8); btns.pack(fill="x")
        ttk.Button(btns, text="SFC 설치", command=self.sfc_install).pack(side="left", padx=4)
        ttk.Button(btns, text="바이패스", command=self.sfc_bypass).pack(side="left", padx=4)
        ttk.Button(btns, text="플로우 조회", command=self.sfc_dump).pack(side="left", padx=4)
        ttk.Button(btns, text="플로우 삭제", command=self.sfc_clear).pack(side="left", padx=4)

        self.out_sfc = scrolledtext.ScrolledText(self.pg_sfc, height=24)
        self.out_sfc.pack(fill="both", expand=True, padx=8, pady=8)

    def log_sfc(self, s): self._append(self.out_sfc, s)

    def _ryu_base(self) -> str:
        host = self.var_rest_host.get().strip()
        port = safe_int(self.var_rest_port.get(), 8080)
        return f"http://{host}:{port}"
    
    # ---- SFC 스켈레톤 핸들러 ----
    def sfc_install(self):
        if requests is None:
            self.log_sfc("requests 모듈 없음 → pip install requests")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        prio = safe_int(self.var_prio.get(), 100)

        h1 = safe_int(self.var_h1.get(), 1)
        fw = safe_int(self.var_fw.get(), 2)
        nat = safe_int(self.var_nat.get(), 3)
        h2 = safe_int(self.var_h2.get(), 4)


        flows = [
            self._flow_add(dpid, prio, h1, fw),
            self._flow_add(dpid, prio, fw, nat),
            self._flow_add(dpid, prio, nat, h2),
        ]

        base = self._ryu_base()
        url = base + "/stats/flowentry/add"
        self.log_sfc(f"[SFC 설치] POST {url}")

        for f in flows:
            try:
                r = requests.post(url, json=f, timeout=3)
                self.log_sfc(f"→ {f['match']} / actions={f['actions']} / status={r.status_code}")
                if r.text:
                    self.log_sfc(r.text.strip())
            except Exception as e:
                self.log_sfc(f"error: {e}")

    def sfc_bypass(self):
        if requests is None:
            self.log_sfc("requests 모듈 없음 → pip install requests")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        prio = safe_int(self.var_prio.get(), 100)
        h1 = safe_int(self.var_h1.get(), 1)
        h2 = safe_int(self.var_h2.get(), 4)

        flow = self._flow_add(dpid, prio, h1, h2)
        base = self._ryu_base()
        url = base + "/stats/flowentry/add"
        self.log_sfc(f"[바이패스] POST {url}")

        try:
            r = requests.post(url, json=flow, timeout=3)
            self.log_sfc(f"→ {flow['match']} / actions={flow['actions']} / status={r.status_code}")
            if r.text:
                self.log_sfc(r.text.strip())
        except Exception as e:
            self.log_sfc(f"error: {e}")

    def sfc_dump(self):
        if requests is None:
            self.log_sfc("requests 모듈 없음 → pip install requests")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        base = self._ryu_base()
        url = base + f"/stats/flow/{dpid}"
        self.log_sfc(f"[플로우 조회] GET {url}")

        try:
            r = requests.get(url, timeout=3)
            self.log_sfc(f"status={r.status_code}")
            try:
                self.log_sfc(json.dumps(r.json(), indent=2, ensure_ascii=False))
            except Exception:
                self.log_sfc(r.text.strip())
        except Exception as e:
            self.log_sfc(f"error: {e}")

    def sfc_clear(self):
        if requests is None:
            self.log_sfc("requests 모듈 없음 → pip install requests")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        base = self._ryu_base()
        url = base + f"/stats/flowentry/clear/{dpid}"
        self.log_sfc(f"[플로우 삭제] DELETE {url}")

        try:
            r = requests.delete(url, timeout=3)
            self.log_sfc(f"status={r.status_code}")
            if r.text:
                self.log_sfc(r.text.strip())
        except Exception as e:
            self.log_sfc(f"error: {e}")

    def _flow_add(self, dpid: int, prio: int, in_port: int, out_port: int) -> dict:
        return {
            "dpid": dpid,
            "priority": prio,
            "match": {"in_port": in_port},
            "actions": [{"type": "OUTPUT", "port": out_port}]
        }

    # ---------------- 공용 ----------------
    def _append(self, widget, text):
        widget.insert("end", text + "\n")
        widget.see("end")

    def on_close(self):
        try:
            self.server_stop()
        except Exception:
            pass
        try:
            self.cli_close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
