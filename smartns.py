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
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"[cmd error] {e}"

def safe_int(s: str, default: int = 0) -> int:
    try:
        return int(s)
    except:
        return default

def pad_fixed(data: bytes, n: int) -> bytes:
    if len(data) > n:
        return data[:n]
    return data + b"\x00" * (n - len(data))

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def recv_until_newline(sock: socket.socket, max_bytes=65536) -> bytes:
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


# ----------------- GUI -----------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("스마트 네트워크 서비스 AD 프로젝트 - 김도경, 배경준, 하승준")
        self.geometry("1180x780")

        self.server_running = False
        self.client_connected = False

        self.server_sock = None
        self.server_thread = None
        self.server_stop_event = threading.Event()
        self.server_lock = threading.Lock()
        self.server_clients: List[ClientConn] = []
        self.server_counter = 0

        self.client_sock = None
        self.client_recv_thread = None
        self.client_stop_event = threading.Event()

        self.draw_send_queue = queue.Queue()

        # Notebook
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

    # ------------------- 네트워크 진단 -------------------
    def _build_diag(self):
        left = ttk.Frame(self.pg_diag, padding=8); left.pack(side="left", fill="y")
        right = ttk.Frame(self.pg_diag, padding=8); right.pack(side="right", fill="both", expand=True)

        ttk.Label(left, text="IP 구성 / netstat / 포트 검사").pack(anchor="w")
        ttk.Button(left, text="IP 구성 확인", command=self.do_ipconfig).pack(fill="x", pady=2)

        self.var_netstat = tk.StringVar(value="9000")
        row = ttk.Frame(left); row.pack(fill="x")
        ttk.Entry(row, textvariable=self.var_netstat, width=10).pack(side="left")
        ttk.Button(row, text="netstat 필터", command=self.do_netstat).pack(side="left", padx=4)

        row2 = ttk.Frame(left); row2.pack(fill="x", pady=4)
        self.var_host = tk.StringVar(value="127.0.0.1")
        self.var_port = tk.StringVar(value="9000")
        ttk.Entry(row2, textvariable=self.var_host, width=14).pack(side="left")
        ttk.Entry(row2, textvariable=self.var_port, width=6).pack(side="left", padx=4)
        ttk.Button(row2, text="포트 검사", command=self.do_check_port).pack(side="left", padx=4)

        ttk.Separator(left).pack(fill="x", pady=6)
        ttk.Label(left, text="바이트/주소 변환").pack(anchor="w")
        ttk.Button(left, text="hton/ntoh", command=self.do_hton).pack(fill="x", pady=2)

        self.var_ipv4 = tk.StringVar(value="8.8.8.8")
        self.var_ipv6 = tk.StringVar(value="2001:4860:4860::8888")

        row3 = ttk.Frame(left); row3.pack(fill="x")
        ttk.Entry(row3, textvariable=self.var_ipv4, width=18).pack(side="left")
        ttk.Button(row3, text="inet_pton/ntop(IPv4)", command=self.do_inet4).pack(side="left", padx=4)

        row4 = ttk.Frame(left); row4.pack(fill="x")
        ttk.Entry(row4, textvariable=self.var_ipv6, width=26).pack(side="left")
        ttk.Button(row4, text="inet_pton/ntop(IPv6)", command=self.do_inet6).pack(side="left", padx=4)

        ttk.Separator(left).pack(fill="x", pady=6)
        ttk.Label(left, text="DNS/역방향 조회").pack(anchor="w")

        self.var_dns = tk.StringVar(value="example.com")
        self.var_rev = tk.StringVar(value="8.8.8.8")

        row5 = ttk.Frame(left); row5.pack(fill="x")
        ttk.Entry(row5, textvariable=self.var_dns, width=18).pack(side="left")
        ttk.Button(row5, text="DNS 조회", command=self.do_dns).pack(side="left", padx=4)

        row6 = ttk.Frame(left); row6.pack(fill="x")
        ttk.Entry(row6, textvariable=self.var_rev, width=18).pack(side="left")
        ttk.Button(row6, text="역방향 조회", command=self.do_reverse).pack(side="left", padx=4)

        self.out_diag = scrolledtext.ScrolledText(right, height=30)
        self.out_diag.pack(fill="both", expand=True)

    def log_diag(self, s):
        self._append(self.out_diag, s)

    def do_ipconfig(self):
        self.log_diag("[IP 구성 확인]")
        if is_windows():
            self.log_diag(run_cmd(["ipconfig", "/all"], timeout=6))
        else:
            out = run_cmd(["ifconfig"], timeout=6)
            if not out.strip():
                out = run_cmd(["ip", "a"], timeout=6)
            self.log_diag(out)

    def do_netstat(self):
        port = self.var_netstat.get().strip()
        self.log_diag("[netstat]")
        if is_windows():
            out = run_cmd(["netstat", "-a", "-n", "-p", "tcp"])
        else:
            out = run_cmd(["netstat", "-anp", "tcp"])
            if "illegal" in out.lower():
                out = run_cmd(["netstat", "-an"])
        filtered = "\n".join([line for line in out.splitlines() if port in line])
        self.log_diag(filtered if filtered else "(no match)")

    def do_check_port(self):
        host = self.var_host.get().strip()
        port = safe_int(self.var_port.get(), 0)
        try:
            with socket.create_connection((host, port), timeout=2):
                self.log_diag("OPEN (연결 성공)")
        except Exception as e:
            self.log_diag(f"CLOSED: {e}")

    def do_hton(self):
        self.log_diag("[hton/ntoh]")
        x16 = 0x1234
        x32 = 0x12345678
        x64 = 0x1122334455667788
        n16 = socket.htons(x16)
        h16 = socket.ntohs(n16)
        n32 = socket.htonl(x32)
        h32 = socket.ntohl(n32)
        n64 = struct.unpack("!Q", struct.pack("@Q", x64))[0]
        h64 = struct.unpack("@Q", struct.pack("!Q", n64))[0]
        self.log_diag(f"16bit {hex(x16)} -> {hex(n16)} -> {hex(h16)}")
        self.log_diag(f"32bit {hex(x32)} -> {hex(n32)} -> {hex(h32)}")
        self.log_diag(f"64bit {hex(x64)} -> {hex(n64)} -> {hex(h64)}")

    def do_inet4(self):
        try:
            ip = self.var_ipv4.get().strip()
            p = socket.inet_pton(socket.AF_INET, ip)
            u = socket.inet_ntop(socket.AF_INET, p)
            self.log_diag(f"packed={p}, unpacked={u}")
        except Exception as e:
            self.log_diag(str(e))

    def do_inet6(self):
        try:
            ip = self.var_ipv6.get().strip()
            p = socket.inet_pton(socket.AF_INET6, ip)
            u = socket.inet_ntop(socket.AF_INET6, p)
            self.log_diag(f"packed={p}, unpacked={u}")
        except Exception as e:
            self.log_diag(str(e))

    def do_dns(self):
        host = self.var_dns.get().strip()
        self.log_diag(f"[DNS] {host}")
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = sorted(set([i[4][0] for i in infos]))
            for a in addrs:
                self.log_diag(a)
        except Exception as e:
            self.log_diag(str(e))

    def do_reverse(self):
        ip = self.var_rev.get().strip()
        try:
            name, alias, addr = socket.gethostbyaddr(ip)
            self.log_diag(f"name={name}")
            self.log_diag(f"addr={addr}")
        except Exception as e:
            self.log_diag(str(e))

    # ------------------- TCP 서버 -------------------

    def _build_server(self):
        top = ttk.Frame(self.pg_server, padding=8); top.pack(fill="x")
        ttk.Label(top, text="포트").pack(side="left")
        self.var_srv_port = tk.StringVar(value="9000")
        ttk.Entry(top, textvariable=self.var_srv_port, width=6).pack(side="left", padx=4)

        self.var_broadcast = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="그림판 브로드캐스트", variable=self.var_broadcast).pack(side="left", padx=4)

        ttk.Button(top, text="서버 시작", command=self.server_start).pack(side="left", padx=4)
        ttk.Button(top, text="서버 정지", command=self.server_stop).pack(side="left", padx=4)

        stat = ttk.Frame(self.pg_server, padding=6); stat.pack(fill="x")
        self.lbl_clients = ttk.Label(stat, text="접속: 0"); self.lbl_clients.pack(side="left")
        self.lbl_counter = ttk.Label(stat, text="카운터: 0"); self.lbl_counter.pack(side="left", padx=12)
        ttk.Button(stat, text="갱신", command=self.server_status).pack(side="left")

        # ---------------------- 클라이언트 리스트 테이블 추가 ----------------------
        tbl_frame = ttk.LabelFrame(self.pg_server, text="접속 클라이언트 목록", padding=4)
        tbl_frame.pack(fill="both", expand=False, padx=6, pady=6)

        self.tbl_clients = ttk.Treeview(tbl_frame, columns=("addr"), show="headings", height=5)
        self.tbl_clients.heading("addr", text="주소 (IP:Port)")
        self.tbl_clients.column("addr", width=250)
        self.tbl_clients.pack(fill="x", expand=True, padx=4, pady=4)

        # 로그창
        self.out_srv = scrolledtext.ScrolledText(self.pg_server, height=22)
        self.out_srv.pack(fill="both", expand=True)

    def update_client_table(self):
        for row in self.tbl_clients.get_children():
            self.tbl_clients.delete(row)
        with self.server_lock:
            for c in self.server_clients:
                self.tbl_clients.insert("", "end", values=(f"{c.addr[0]}:{c.addr[1]}",))

    def log_srv(self, s):
        self._append(self.out_srv, s)

    def server_start(self):
        if self.server_running:
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
            messagebox.showerror("서버 실패", str(e))
            return

        self.server_running = True
        self.log_srv(f"[서버 시작] {port}")

        self.server_thread = threading.Thread(target=self._server_accept_loop, daemon=True)
        self.server_thread.start()

        threading.Thread(target=self._server_draw_broadcast_loop, daemon=True).start()

    def _server_accept_loop(self):
        srv = self.server_sock
        while not self.server_stop_event.is_set():
            try:
                srv.settimeout(1.0)
                cli, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            th = threading.Thread(target=self._server_client_loop, args=(cli, addr), daemon=True)
            conn = ClientConn(sock=cli, addr=addr, thread=th)

            with self.server_lock:
                self.server_clients.append(conn)

            th.start()
            self.log_srv(f"[접속] {addr}")
            self.update_client_table()
            self.server_status()

    def _server_client_loop(self, cli: socket.socket, addr):
        cli.settimeout(1.0)
        try:
            while not self.server_stop_event.is_set():
                try:
                    mode = cli.recv(1)
                    if not mode:
                        break
                    mode = mode.decode()

                    if mode == "V":
                        data = recv_until_newline(cli)
                        msg = data.decode().rstrip("\n")
                        self._server_on_message(addr, f"VAR '{msg}'")
                        cli.sendall(b"V" + data)

                    elif mode == "F":
                        data = recv_exact(cli, 32)
                        msg = data.rstrip(b"\x00").decode()
                        self._server_on_message(addr, f"FIXED '{msg}'")
                        cli.sendall(b"F" + data)

                    elif mode == "M":
                        hdr = recv_exact(cli, 4)
                        n = struct.unpack("!I", hdr)[0]
                        payload = recv_exact(cli, n)
                        msg = payload.decode()
                        self._server_on_message(addr, f"MIX '{msg}' len={n}")
                        cli.sendall(b"M" + hdr + payload)

                    elif mode == "D":
                        payload = recv_exact(cli, 16)
                        if self.var_broadcast.get():
                            self.draw_send_queue.put(payload)
                        self._server_on_message(addr, "DRAW event")

                    else:
                        self._server_on_message(addr, f"UNKNOWN={mode}")

                except socket.timeout:
                    continue

        except Exception as e:
            self.log_srv(f"[오류] {addr}: {e}")

        finally:
            cli.close()
            with self.server_lock:
                self.server_clients = [c for c in self.server_clients if c.addr != addr]

            self.log_srv(f"[해제] {addr}")
            self.update_client_table()
            self.server_status()

    def _server_on_message(self, addr, text):
        with self.server_lock:
            self.server_counter += 1
            c = self.server_counter
        self.log_srv(f"[{addr}] {text} | counter={c}")

    def _server_draw_broadcast_loop(self):
        while not self.server_stop_event.is_set():
            try:
                payload = self.draw_send_queue.get(timeout=1)
            except queue.Empty:
                continue

            dead = []
            with self.server_lock:
                for c in self.server_clients:
                    try:
                        c.sock.sendall(b"D" + payload)
                    except:
                        dead.append(c.addr)

                if dead:
                    self.server_clients = [x for x in self.server_clients if x.addr not in dead]

            self.update_client_table()

    def server_stop(self):
        if not self.server_running:
            return
        self.server_stop_event.set()
        try:
            self.server_sock.close()
        except:
            pass

        with self.server_lock:
            for c in self.server_clients:
                try: c.sock.close()
                except: pass
            self.server_clients.clear()

        self.server_running = False
        self.update_client_table()
        self.server_status()
        self.log_srv("[서버 정지 완료]")

    def server_status(self):
        with self.server_lock:
            n = len(self.server_clients)
            cnt = self.server_counter
        self.lbl_clients.config(text=f"접속: {n}")
        self.lbl_counter.config(text=f"카운터: {cnt}")

    # ------------------- TCP 클라이언트 -------------------

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
        ttk.Radiobutton(opt, text="FIXED(32B)", variable=self.var_mode, value="FIXED").pack(side="left", padx=4)
        ttk.Radiobutton(opt, text="MIX", variable=self.var_mode, value="MIX").pack(side="left", padx=4)

        self.var_after_close = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="전송 후 종료", variable=self.var_after_close).pack(side="left")

        msg = ttk.Frame(self.pg_client, padding=8); msg.pack(fill="x")
        self.var_msg = tk.StringVar(value="hello")
        ttk.Entry(msg, textvariable=self.var_msg, width=60).pack(side="left")
        ttk.Button(msg, text="전송", command=self.cli_send).pack(side="left", padx=4)

        self.out_cli = scrolledtext.ScrolledText(self.pg_client, height=28)
        self.out_cli.pack(fill="both", expand=True)

    def log_cli(self, s):
        self._append(self.out_cli, s)

    def cli_connect(self):
        if self.client_connected:
            return

        host = self.var_cli_host.get().strip()
        port = safe_int(self.var_cli_port.get(), 9000)

        try:
            self.client_sock = socket.create_connection((host, port), timeout=3)
            self.client_sock.settimeout(1)
        except Exception as e:
            messagebox.showerror("연결 실패", str(e))
            return

        self.client_connected = True
        self.log_cli(f"[연결됨] {host}:{port}")

        self.client_stop_event.clear()
        self.client_recv_thread = threading.Thread(target=self._cli_recv_loop, daemon=True)
        self.client_recv_thread.start()

    def _cli_recv_loop(self):
        sock = self.client_sock
        try:
            while not self.client_stop_event.is_set():
                try:
                    mode = sock.recv(1)
                    if not mode:
                        break
                    mode = mode.decode()

                    if mode == "V":
                        data = recv_until_newline(sock)
                        msg = data.decode().rstrip("\n")
                        self.log_cli(f"[VAR] {msg}")

                    elif mode == "F":
                        data = recv_exact(sock, 32)
                        msg = data.rstrip(b"\x00").decode()
                        self.log_cli(f"[FIXED] {msg}")

                    elif mode == "M":
                        hdr = recv_exact(sock, 4)
                        n = struct.unpack("!I", hdr)[0]
                        payload = recv_exact(sock, n)
                        msg = payload.decode()
                        self.log_cli(f"[MIX] {msg}")

                    elif mode == "D":
                        payload = recv_exact(sock, 16)
                        x1, y1, x2, y2 = struct.unpack("!IIII", payload)
                        self._draw_remote_line(x1, y1, x2, y2)

                except socket.timeout:
                    continue

        except Exception as e:
            self.log_cli(f"{e}")

        finally:
            self.log_cli("[수신 종료]")
            self._cli_cleanup()

    def _cli_cleanup(self):
        try:
            if self.client_sock:
                self.client_sock.close()
        except:
            pass
        self.client_sock = None
        self.client_connected = False

    def cli_close(self):
        if not self.client_connected:
            return
        self.client_stop_event.set()
        try:
            if self.client_sock:
                self.client_sock.close()
        except:
            pass
        self.client_connected = False
        self.log_cli("[연결 해제]")

    def cli_send(self):
        if not self.client_connected or not self.client_sock:
            return

        mode = self.var_mode.get()
        msg = self.var_msg.get()
        data = msg.encode()

        try:
            if mode == "VAR":
                self.client_sock.sendall(b"V" + data + b"\n")
            elif mode == "FIXED":
                self.client_sock.sendall(b"F" + pad_fixed(data, 32))
            elif mode == "MIX":
                hdr = struct.pack("!I", len(data))
                self.client_sock.sendall(b"M" + hdr + data)

            self.log_cli(f"[송신] {msg}")

            if self.var_after_close.get():
                self.cli_close()

        except Exception as e:
            self.log_cli(f"[오류] {e}")
            self.cli_close()

    # ------------------- 버퍼/소켓 -------------------

    def _build_buf(self):
        top = ttk.Frame(self.pg_buf, padding=8); top.pack(fill="x")
        ttk.Button(top, text="클라 소켓 버퍼 조회", command=self.buf_client).pack(side="left", padx=4)
        ttk.Button(top, text="임시 소켓 버퍼 조회", command=self.buf_temp).pack(side="left", padx=4)

        self.out_buf = scrolledtext.ScrolledText(self.pg_buf, height=30)
        self.out_buf.pack(fill="both", expand=True)

    def log_buf(self, s): self._append(self.out_buf, s)

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


    # ------------------- 그림판 -------------------

    def _build_draw(self):
        ttk.Label(self.pg_draw, text="그림판 — 드래그 시 선, 서버가 브로드캐스트 ").pack(anchor="w", padx=8, pady=4)

        self.canvas = tk.Canvas(self.pg_draw, bg="white", height=520)
        self.canvas.pack(fill="both", expand=True, padx=8, pady=8)

        self.canvas.bind("<ButtonPress-1>", self._draw_start)
        self.canvas.bind("<B1-Motion>", self._draw_move)
        self._last_xy = None

    def _draw_start(self, e):
        self._last_xy = (e.x, e.y)

    def _draw_move(self, e):
        if not self._last_xy:
            return
        x1, y1 = self._last_xy
        x2, y2 = e.x, e.y
        self.canvas.create_line(x1, y1, x2, y2)

        if self.client_connected and self.client_sock:
            try:
                payload = struct.pack("!IIII", x1, y1, x2, y2)
                self.client_sock.sendall(b"D" + payload)
            except:
                pass

        self._last_xy = (x2, y2)

    def _draw_remote_line(self, x1, y1, x2, y2):
        def draw():
            self.canvas.create_line(x1, y1, x2, y2)
        self.after(0, draw)

    # ------------------- Ryu SFC -------------------

    def _build_sfc(self):
        top = ttk.Frame(self.pg_sfc, padding=8)
        top.pack(fill="x")

        self.var_rest_host = tk.StringVar(value="127.0.0.1")
        self.var_rest_port = tk.StringVar(value="8080")
        self.var_dpid = tk.StringVar(value="1")
        self.var_prio = tk.StringVar(value="100")
        self.var_h1 = tk.StringVar(value="1")
        self.var_fw = tk.StringVar(value="2")
        self.var_nat = tk.StringVar(value="3")
        self.var_h2 = tk.StringVar(value="4")

        ttk.Label(top, text="REST").grid(row=0, column=0)
        ttk.Entry(top, textvariable=self.var_rest_host, width=14).grid(row=0, column=1)
        ttk.Label(top, text=":").grid(row=0, column=2)
        ttk.Entry(top, textvariable=self.var_rest_port, width=6).grid(row=0, column=3)

        ttk.Label(top, text="DPID").grid(row=0, column=4)
        ttk.Entry(top, textvariable=self.var_dpid, width=6).grid(row=0, column=5)

        ttk.Label(top, text="prio").grid(row=0, column=6)
        ttk.Entry(top, textvariable=self.var_prio, width=6).grid(row=0, column=7)

        ports = ttk.Frame(self.pg_sfc, padding=6)
        ports.pack(fill="x")
        for i, (label, var) in enumerate([("h1", self.var_h1), ("fw", self.var_fw), ("nat", self.var_nat), ("h2", self.var_h2)]):
            ttk.Label(ports, text=label).grid(row=0, column=i * 2)
            ttk.Entry(ports, textvariable=var, width=6).grid(row=0, column=i * 2 + 1, padx=4)

        btns = ttk.Frame(self.pg_sfc, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="SFC 설치", command=self.sfc_install).pack(side="left", padx=4)
        ttk.Button(btns, text="바이패스", command=self.sfc_bypass).pack(side="left", padx=4)
        ttk.Button(btns, text="플로우 조회", command=self.sfc_dump).pack(side="left", padx=4)
        ttk.Button(btns, text="플로우 삭제", command=self.sfc_clear).pack(side="left", padx=4)

        # ----------- 테이블 시각화 추가 -------------
        tbl_frame = ttk.LabelFrame(self.pg_sfc, text="SFC Flow Entries", padding=6)
        tbl_frame.pack(fill="both", expand=False, padx=6, pady=6)

        self.tbl_sfc = ttk.Treeview(tbl_frame, columns=("prio", "match", "actions"), show="headings", height=8)
        self.tbl_sfc.heading("prio", text="Priority")
        self.tbl_sfc.heading("match", text="Match")
        self.tbl_sfc.heading("actions", text="Actions")

        self.tbl_sfc.column("prio", width=80)
        self.tbl_sfc.column("match", width=300)
        self.tbl_sfc.column("actions", width=300)

        self.tbl_sfc.pack(fill="x", expand=False)

        self.out_sfc = scrolledtext.ScrolledText(self.pg_sfc, height=18)
        self.out_sfc.pack(fill="both", expand=True)

    def log_sfc(self, s):
        self._append(self.out_sfc, s)

    def _ryu_base(self):
        host = self.var_rest_host.get().strip()
        port = safe_int(self.var_rest_port.get(), 8080)
        return f"http://{host}:{port}"

    def sfc_install(self):
        if requests is None:
            self.log_sfc("requests 모듈 없음")
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

        url = self._ryu_base() + "/stats/flowentry/add"
        for f in flows:
            try:
                r = requests.post(url, json=f, timeout=3)
                self.log_sfc(f"ADD match={f['match']} actions={f['actions']}")
            except Exception as e:
                self.log_sfc(str(e))

    def sfc_bypass(self):
        if requests is None:
            self.log_sfc("requests 없음")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        prio = safe_int(self.var_prio.get(), 100)
        h1 = safe_int(self.var_h1.get(), 1)
        h2 = safe_int(self.var_h2.get(), 4)

        flow = self._flow_add(dpid, prio, h1, h2)

        url = self._ryu_base() + "/stats/flowentry/add"
        try:
            r = requests.post(url, json=flow, timeout=3)
            self.log_sfc(f"BYPASS: {flow}")
        except Exception as e:
            self.log_sfc(str(e))

    def sfc_dump(self):
        if requests is None:
            self.log_sfc("requests 없음")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        url = self._ryu_base() + f"/stats/flow/{dpid}"

        try:
            r = requests.get(url, timeout=3)
            self.log_sfc(f"status {r.status_code}")

            try:
                data = r.json()
            except:
                self.log_sfc(r.text)
                return

            self._update_sfc_table(data)

            self.log_sfc(json.dumps(data, indent=2, ensure_ascii=False))

        except Exception as e:
            self.log_sfc(str(e))

    def _update_sfc_table(self, data):
        for row in self.tbl_sfc.get_children():
            self.tbl_sfc.delete(row)

        flows = data.get("1", [])
        for f in flows:
            pr = f.get("priority", "")
            mt = json.dumps(f.get("match", {}), ensure_ascii=False)
            ac = json.dumps(f.get("actions", []), ensure_ascii=False)
            self.tbl_sfc.insert("", "end", values=(pr, mt, ac))

    def sfc_clear(self):
        if requests is None:
            self.log_sfc("requests 없음")
            return

        dpid = safe_int(self.var_dpid.get(), 1)
        url = self._ryu_base() + f"/stats/flowentry/clear/{dpid}"

        try:
            r = requests.delete(url, timeout=3)
            self.log_sfc("[삭제 완료]")
        except Exception as e:
            self.log_sfc(str(e))

    def _flow_add(self, dpid, prio, in_port, out_port):
        return {
            "dpid": dpid,
            "priority": prio,
            "match": {"in_port": in_port},
            "actions": [{"type": "OUTPUT", "port": out_port}],
        }

    # ---------------- 공용 -------------------

    def _append(self, widget, text):
        widget.insert("end", text + "\n")
        widget.see("end")

    def on_close(self):
        try:
            self.server_stop()
        except:
            pass
        try:
            self.cli_close()
        except:
            pass
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
