import os
import shutil
import socket
import subprocess
import tempfile
import time

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite import HandshakeSettings, TLSConnection


TESTS_DIR = os.path.join(os.path.dirname(__file__), "..", "tests")


@unittest.skipUnless(shutil.which("openssl"),
                     "openssl executable is not available")
class TestOpenSSLTLS13Interop(unittest.TestCase):
    def setUp(self):
        self.process = None
        self.log = tempfile.TemporaryFile(mode="w+b")
        self.port = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]

        command = [
            "openssl", "s_server",
            "-accept", str(self.port),
            "-naccept", "2",
            "-www",
            "-tls1_3",
            "-num_tickets", "1",
            "-cert", os.path.join(TESTS_DIR, "serverX509Cert.pem"),
            "-key", os.path.join(TESTS_DIR, "serverX509Key.pem"),
            "-quiet",
        ]
        self.process = subprocess.Popen(
            command,
            stdout=self.log,
            stderr=subprocess.STDOUT)

        deadline = time.time() + 5
        while time.time() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                self.skipTest(self.log.read())
            checker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            checker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            checker.settimeout(0.05)
            try:
                checker.bind(("127.0.0.1", self.port))
                time.sleep(0.05)
            except socket.error:
                return
            finally:
                checker.close()
        self.skipTest("openssl s_server did not become ready")

    def tearDown(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        self.log.close()

    def _connect(self, session=None):
        raw_socket = socket.create_connection(
            ("127.0.0.1", self.port), timeout=5)
        connection = TLSConnection(raw_socket)
        settings = HandshakeSettings()
        settings.minVersion = (3, 4)
        settings.maxVersion = (3, 4)
        connection.handshakeClientCert(
            serverName="localhost",
            settings=settings,
            session=session)
        return connection

    def test_handshake_and_session_resumption(self):
        if self.process.poll() is not None:
            self.log.seek(0)
            self.fail(self.log.read())
        first = self._connect()
        self.assertEqual((3, 4), first.version)
        first.read(min=0)
        self.assertTrue(first.session.tickets)
        session = first.session
        first.close()

        second = self._connect(session)
        self.assertEqual((3, 4), second.version)
        self.assertTrue(second.resumed)
        second.close()

        self.process.wait(5)


if __name__ == "__main__":
    unittest.main()
