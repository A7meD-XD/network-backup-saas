"""Local Paramiko SSH mock for exercising the Cisco IOS Netmiko workflow."""

import logging
import socket
import threading

import paramiko


HOST = "127.0.0.1"
PORT = 2222
USERNAME = "admin"
PASSWORD = "admin123"
PROMPT = "mock-router#"

RUNNING_CONFIG = """!
version 15.2
hostname mock-router
no ip domain-lookup
!
snmp-server community public RO
!
interface GigabitEthernet0/0
 description Local mock management interface
 ip address 192.0.2.1 255.255.255.0
 no shutdown
!
line con 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
!
end"""


class MockRouterSSHServer(paramiko.ServerInterface):
    """Accept only the documented local test credentials and a shell channel."""

    def __init__(self) -> None:
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, channel_id: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: str,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
        modes: dict,
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True


def send_text(channel: paramiko.Channel, text: str) -> None:
    channel.sendall(text.encode("utf-8"))


def handle_client(client: socket.socket) -> None:
    transport = paramiko.Transport(client)
    channel = None
    try:
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        server = MockRouterSSHServer()
        transport.start_server(server=server)
        channel = transport.accept(timeout=15)
        if channel is None or not server.shell_requested.wait(timeout=10):
            return

        channel.settimeout(1.0)
        send_text(channel, f"\r\n{PROMPT}")
        pending = ""
        while transport.is_active() and not channel.closed:
            try:
                received = channel.recv(4096)
            except socket.timeout:
                continue
            if not received:
                break

            pending += received.decode("utf-8", errors="ignore")
            while "\n" in pending:
                raw_command, pending = pending.split("\n", 1)
                command = raw_command.rstrip("\r").strip()
                send_text(channel, f"{command}\r\n")

                if not command:
                    send_text(channel, PROMPT)
                elif command.lower().startswith("terminal "):
                    send_text(channel, PROMPT)
                elif command.lower() in {"show running-config", "show run", "sh run"}:
                    send_text(channel, f"{RUNNING_CONFIG}\r\n{PROMPT}")
                elif command.lower() in {"exit", "logout"}:
                    send_text(channel, "Connection closed.\r\n")
                    return
                else:
                    send_text(channel, f"% Unsupported mock command: {command}\r\n{PROMPT}")
    except (EOFError, OSError, paramiko.SSHException) as exc:
        logging.info("Mock SSH client disconnected: %s", exc)
    finally:
        if channel is not None:
            try:
                channel.close()
            except (EOFError, OSError, paramiko.SSHException):
                pass
        transport.close()
        client.close()


def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(20)
        print(f"Mock Cisco SSH server listening on {HOST}:{PORT}")
        try:
            while True:
                client, address = listener.accept()
                logging.info("SSH connection from %s:%s", *address)
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            print("Stopping mock SSH server.")


if __name__ == "__main__":
    serve()
