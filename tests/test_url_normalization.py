import contextlib
import io
from pathlib import Path
import runpy
import sys
import unittest
from urllib.parse import urlsplit
from unittest.mock import Mock, patch

from url_normalization import normalize_url_hostname

UNICODE_URL = "http://cartemembre.lavitaèbella.eu"
ASCII_URL = "http://cartemembre.xn--lavitabella-39a.eu"
ROOT = Path(__file__).resolve().parents[1]


class URLNormalizationTests(unittest.TestCase):
    def test_reported_url(self):
        self.assertEqual(normalize_url_hostname(UNICODE_URL), ASCII_URL)

    def test_preserves_other_components(self):
        self.assertEqual(
            normalize_url_hostname(
                "https://usér:p%40ss@lavitaèbella.eu:8443/été%2F?q=è#à"
            ),
            "https://usér:p%40ss@xn--lavitabella-39a.eu:8443/été%2F?q=è#à",
        )

    def test_preserves_ascii_and_ip_urls(self):
        for url in (
            ASCII_URL,
            "https://example.org/a?x=1#b",
            "http://192.0.2.1:8080/",
            "http://[2001:db8::1]:8080/",
            "https://example.org/?#",
        ):
            with self.subTest(url=url):
                self.assertEqual(normalize_url_hostname(url), url)

    def test_unicode_normalization_and_idna_2008(self):
        for host, expected in (
            ("LAVITAÈBELLA.eu", "xn--lavitabella-39a.eu"),
            ("lavitae\u0300bella.eu", "xn--lavitabella-39a.eu"),
            ("faß.de", "xn--fa-hia.de"),
        ):
            with self.subTest(host=host):
                self.assertEqual(
                    normalize_url_hostname("https://" + host), "https://" + expected
                )

    def test_rejects_invalid_hosts(self):
        for url in (
            "http://",
            "http://bad host.eu",
            "http://☃.eu",
            "http://bad\nhost.eu",
            "http://[invalid]/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_url_hostname(url)


class TicketFlowTests(unittest.TestCase):
    def run_flow(
        self,
        result=None,
        failure=None,
        url=UNICODE_URL,
        redirect="https://faß.de/été?q=è",
    ):
        tracker = Mock()
        tracker.create_ticket.return_value = 123
        abuse = Mock()
        abuse.run_query.return_value = {
            "digest": ["details", ["abuse@example.org"], ["AS123"]],
            "result": [{UNICODE_URL: {}}, {redirect: {}}],
        }
        misp = Mock()
        misp.search.return_value = {"response": {"Attribute": []}}
        misp.add_object.return_value = result
        misp.add_object.side_effect = failure
        obj = Mock()
        # FAUP's native library is not required for these mocked flow tests.
        self.faup = Mock()
        self.faup.get_host.side_effect = lambda: urlsplit(
            self.faup.decode.call_args.args[0]
        ).hostname.upper()
        modules = {
            "config": Mock(
                ua="test",
                rt_url="https://rt.invalid",
                rt_user="test",
                rt_pass="test",
                known_good_excludelist=[],
            ),
            "keys": Mock(
                misp_url="https://misp.invalid", misp_key="test", misp_verifycert=True
            ),
            "rt": Mock(Rt=Mock(return_value=tracker), RtError=RuntimeError),
            "pyurlabuse": Mock(PyURLAbuse=Mock(return_value=abuse)),
            "pymisp": Mock(
                PyMISP=Mock(return_value=misp), MISPObject=Mock(return_value=obj)
            ),
            "ioc_fanger": Mock(defang=lambda value: value),
            "pyfaup": Mock(),
            "pyfaup.faup": Mock(Faup=Mock(return_value=self.faup)),
        }
        argv = [
            str(ROOT / "create_ticket_with_template.py"),
            "42",
            str(ROOT / "templates/phishing_server.tmpl"),
            url,
            "0",
            "36",
            "418648",
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        status = 0
        with patch.dict(sys.modules, modules), patch.object(sys, "argv", argv), patch(
            "time.sleep"
        ), patch("os.path.exists", return_value=False), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(
            stderr
        ):
            try:
                runpy.run_path(argv[0], run_name="__main__")
            except SystemExit as error:
                status = error.code
        return status, stdout.getvalue(), stderr.getvalue(), tracker, abuse, misp, obj

    def test_normalizes_lookup_search_and_misp_attributes(self):
        status, out, err, tracker, abuse, misp, obj = self.run_flow(
            {"Object": {"id": "99"}}
        )
        self.assertEqual(status, 0)
        self.assertIn("Information added to MISP.", out)
        self.assertEqual(err, "")
        self.assertEqual(
            [call.args[0] for call in self.faup.decode.call_args_list],
            [UNICODE_URL, ASCII_URL, ASCII_URL, "https://xn--fa-hia.de/été?q=è"],
        )
        for call in abuse.run_query.call_args_list:
            self.assertEqual(call.args[0], ASCII_URL)
        misp.search.assert_called_once_with(
            controller="attributes", eventid="418648", value=ASCII_URL
        )
        obj.add_attribute.assert_any_call(
            "hostname", value="cartemembre.xn--lavitabella-39a.eu"
        )
        obj.add_attribute.assert_any_call("url", value=ASCII_URL, comment="initial URL")
        obj.add_attribute.assert_any_call(
            "url-redirect",
            value="https://xn--fa-hia.de/été?q=è",
            comment="redirect URL: 1",
        )
        obj.add_attribute.assert_any_call(
            "hostname", value="xn--fa-hia.de", to_ids=False
        )
        tracker.create_ticket.assert_called_once()

    def test_misp_failures_never_report_success(self):
        for response in (
            {"saved": False, "errors": "Hostname has an invalid format."},
            {"errors": ["403"]},
            {},
            None,
        ):
            with self.subTest(response=response):
                status, out, err, tracker, _, _, _ = self.run_flow(response)
                self.assertEqual(status, 1)
                self.assertNotIn("Information added to MISP.", out)
                self.assertIn("RT ticket already created", err)
                tracker.create_ticket.assert_called_once()

    def test_misp_exception_never_reports_success(self):
        status, out, err, *_ = self.run_flow(failure=RuntimeError("network failure"))
        self.assertEqual(status, 1)
        self.assertNotIn("Information added to MISP.", out)
        self.assertIn("MISP object save failed", err)

    def test_invalid_input_fails_before_ticket_creation(self):
        status, _, _, tracker, abuse, _, _ = self.run_flow(url="http://☃.eu")
        self.assertEqual(status, 1)
        tracker.create_ticket.assert_not_called()
        abuse.run_query.assert_not_called()

    def test_invalid_redirect_fails_before_ticket_creation(self):
        status, _, _, tracker, _, misp, _ = self.run_flow(redirect="http://☃.eu")
        self.assertEqual(status, 1)
        tracker.create_ticket.assert_not_called()
        misp.add_object.assert_not_called()


if __name__ == "__main__":
    unittest.main()
