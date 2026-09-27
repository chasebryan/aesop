"""
Tests for the graphical workbench (``aesop gui``).

Most of the workbench is deliberately toolkit-free — output capture, the
form/argv mapping, the Markdown subset, the inspector's statistics and the
worker protocol — and is tested here without a display.  The window itself is
smoke-tested at the end when Tk and a display are available, and skipped
otherwise.
"""
from __future__ import annotations

import os
import queue
import time

import pytest

from aesop import cli
from aesop.manual import load_manual
from aesop.registry import REGISTRY, resolve

cli._load_modules()

from aesop.gui import forms, insight  # noqa: E402
from aesop.gui import markdown as md  # noqa: E402
from aesop.gui.capture import (CaptureOutput, events_to_text, is_style,  # noqa: E402
                               parse_markup, plain)
from aesop.gui.runner import CANCELLED, Runner  # noqa: E402


# --------------------------------------------------------------------------- #
# capture
# --------------------------------------------------------------------------- #
def test_markup_styles_are_split_into_spans():
    assert parse_markup("[bold red]HIGH[/] risk") == [("HIGH", "bold red"), (" risk", "")]
    assert parse_markup("[dim]a [bold]b[/][/] c") == [
        ("a ", "dim"), ("b", "dim bold"), (" c", "")]


@pytest.mark.parametrize("text", [
    "key[0] = 5", "[abc]", "flag{x} [not a style]", "matrix [[1, 2], [3, 4]]", "[/] stray",
])
def test_bracketed_data_is_never_swallowed(text):
    """Handlers interpolate untrusted data; it must come through verbatim."""
    assert plain(parse_markup(text)) == text


def test_escaped_bracket_is_literal():
    assert plain(parse_markup(r"\[bold]x")) == "[bold]x"


def test_is_style():
    assert is_style("bold #d97706") and is_style("red on white") and is_style("dim")
    assert not is_style("abc") and not is_style("") and not is_style("bold nonsense")


def test_capture_records_every_output_call():
    events = []
    out = CaptureOutput(events.append)
    out.success("found [bold]it[/]")
    out.print()
    out.raw("PLAINTEXT")
    out.table(["k", "v"], [(1, b"by\x00tes"), ("[red]x[/]", "[1]")], title="[bold]T[/]")
    out.keyval([("a", 1)], title="kv")
    out.panel("body", title="p")
    out.rule("r")
    out.error("bad")
    assert [e["kind"] for e in events] == [
        "line", "blank", "raw", "table", "keyval", "panel", "rule", "line"]
    table = events[3]
    assert table["title"] == "T" and table["columns"] == ["k", "v"]
    assert table["rows"][0] == [["1", ""], ["by\x00tes", ""]]
    assert table["rows"][1] == [["x", "red"], ["[1]", ""]]
    text = events_to_text(events)
    assert "✓ found it" in text and "PLAINTEXT" in text and "✗ bad" in text


def test_capture_pretends_to_be_rich_but_never_prints(capsys):
    out = CaptureOutput(lambda ev: None)
    assert out._rich is True
    out.raw("x")
    out.error("y")
    assert capsys.readouterr() == ("", "")


# --------------------------------------------------------------------------- #
# forms
# --------------------------------------------------------------------------- #
def test_every_command_yields_a_form():
    for name, cmd in REGISTRY.items():
        fields = forms.fields_for(cmd)
        assert len(fields) == len(cmd.args), name
        dests = [f.dest for f in fields]
        assert len(set(dests)) == len(dests), f"{name}: duplicate dest"
        # an empty form must still produce a parseable invocation
        assert forms.build_argv(cmd, {}) == [name]


def test_field_kinds():
    kinds = {f.dest: f.kind for f in forms.fields_for(resolve("caesar"))}
    assert kinds == {"text": forms.INPUT, "file": forms.PATH, "in_encoding": forms.CHOICE,
                     "shift": forms.INT, "encode": forms.FLAG, "all": forms.FLAG,
                     "top": forms.INT}
    rsa = {f.dest: f for f in forms.fields_for(resolve("rsa"))}
    assert rsa["n"].kind == forms.LIST and rsa["n"].flag == "--modulus"
    pcap = {f.dest: f for f in forms.fields_for(resolve("pcap"))}
    assert pcap["file"].kind == forms.PATH and pcap["file"].required
    assert pcap["carve"].kind == forms.DIR


def test_build_argv_omits_defaults_and_empties():
    cmd = resolve("caesar")
    argv = forms.build_argv(cmd, {"text": "Uryyb", "in_encoding": "auto", "top": "3",
                                  "shift": "", "all": True, "encode": False})
    assert argv == ["caesar", "--all", "Uryyb"]
    assert forms.command_line(argv) == "aesop caesar --all Uryyb"


def test_build_argv_protects_values_that_look_like_flags():
    argv = forms.build_argv(resolve("caesar"), {"text": "-- .- -", "shift": "-3"})
    assert argv == ["caesar", "--shift=-3", "--", "-- .- -"]
    args = cli.build_parser().parse_args(argv)
    assert args.shift == -3 and args.text == "-- .- -"
    # a short-only option
    argv = forms.build_argv(resolve("affine"), {"a": "-5", "text": "x"})
    assert cli.build_parser().parse_args(argv).a == -5


def test_repeatable_options_expand():
    argv = forms.build_argv(resolve("rsa"), {"n": "0x21 35\n77", "e": ["3"]})
    assert argv == ["rsa", "--modulus", "0x21", "--modulus", "35", "--modulus", "77",
                    "--exponent", "3"]
    assert cli.build_parser().parse_args(argv).n == [33, 35, 77]


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_form_values_round_trip_through_the_real_parser(name):
    """What the form builds, the CLI parser must accept — for every command."""
    cmd = resolve(name)
    values = {}
    for f in forms.fields_for(cmd):
        if f.kind == forms.FLAG:
            values[f.dest] = True
        elif f.kind == forms.CHOICE:
            values[f.dest] = f.choices[-1]
        elif f.kind in (forms.INT, forms.FLOAT):
            values[f.dest] = "7"
        elif f.kind == forms.LIST:
            values[f.dest] = ["11", "13"]
        elif f.dest == "keylen":
            values[f.dest] = "16"
        else:
            values[f.dest] = "some value"
        if f.dest in ("modulus", "B", "max_iters", "p", "q", "d", "phi"):
            values[f.dest] = "7"
    argv = forms.build_argv(cmd, values)
    args = cli.build_parser().parse_args(argv)
    assert args._cmd is cmd
    for f in forms.fields_for(cmd):
        assert getattr(args, f.dest) not in (None, False, []), f"{name}: {f.dest} was lost"
    # and the form can be refilled from that argv
    again = forms.values_from_argv(cmd, argv[1:])
    assert forms.build_argv(cmd, again) == argv


def test_missing_required():
    cmd = resolve("pcap")
    assert [f.dest for f in forms.missing_required(cmd, {})] == ["file"]
    assert forms.missing_required(cmd, {"file": "x.pcap"}) == []


def test_parse_example():
    assert forms.parse_example("aesop caesar --all 'Uryyb Jbeyq'   # a comment") == \
        ("caesar", ["--all", "Uryyb Jbeyq"], None)
    assert forms.parse_example("$ echo 'Fdhvdu flskhu' | aesop caesar") == \
        ("caesar", [], "Fdhvdu flskhu")
    assert forms.parse_example("python -m aesop morse -d '... --- ...'") == \
        ("morse", ["-d", "... --- ..."], None)
    for unsupported in ("cat x | aesop xor --top 5", "aesop rsa -n 0x... -e 65537",
                        "aesop crack -w words.txt <digest>", "ls -la",
                        "echo hi | aesop b64 | aesop b64 -d", "aesop b64 'unterminated"):
        assert forms.parse_example(unsupported) is None, unsupported


def test_most_documented_examples_load_into_a_form():
    total = loadable = 0
    for cmd in REGISTRY.values():
        for ex in cmd.examples:
            total += 1
            parsed = forms.parse_example(ex)
            if parsed is None:
                continue
            target = resolve(parsed[0])
            assert target is not None, ex
            forms.values_from_argv(target, parsed[1])       # must not raise
            loadable += 1
    assert total and loadable / total > 0.7


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def test_markdown_blocks():
    blocks = md.parse(
        "# Title\n> summary\n\nSome **bold `code`** and *it* text\nwrapped.\n\n"
        "```console\n$ aesop caesar x\n```\n\n"
        "1. one\n   - nested item\n     continued\n2. two\n\n"
        "| a | b |\n|---|---|\n| `x|y` | z |\n\n---\n")
    assert [b.kind for b in blocks] == [
        "heading", "quote", "para", "code", "item", "item", "item", "table", "rule"]
    assert blocks[0].level == 1 and md.inline_text(blocks[0].spans) == "Title"
    assert md.inline_text(blocks[2].spans) == "Some bold code and it text wrapped."
    assert ("code", ("bold", "code"), "") in blocks[2].spans
    assert blocks[3].lang == "console" and blocks[3].text == "$ aesop caesar x"
    assert (blocks[4].marker, blocks[4].level) == ("1.", 0)
    assert (blocks[5].marker, blocks[5].level) == ("•", 1)
    assert md.inline_text(blocks[5].spans) == "nested item continued"
    assert [md.inline_text(c) for c in blocks[7].rows[0]] == ["x|y", "z"]


def test_markdown_inline_edge_cases():
    assert md.inline_text(md.parse_inline("2*3*4 and snake_case_name")) == \
        "2*3*4 and snake_case_name"
    assert md.parse_inline("[docs](https://example.invalid)") == [
        ("docs", (), "https://example.invalid")]


def test_every_manual_page_parses_cleanly():
    for slug, page in load_manual().items():
        blocks = md.parse(page.body())
        assert blocks and blocks[0].kind == "heading", slug
        for b in blocks:
            text = md.inline_text(b.spans)
            assert "**" not in text and "`" not in text, f"{slug}: unparsed markup in {text!r}"
            for row in b.rows:
                assert len(row) == len(b.header), f"{slug}: ragged table"


# --------------------------------------------------------------------------- #
# insight
# --------------------------------------------------------------------------- #
def test_insight_on_text():
    info = insight.analyse("It was a bright cold day in April, and the clocks were "
                           "striking thirteen. " * 4)
    assert info.encoding == "raw" and info.texty and not info.empty
    assert 0.06 < info.ic < 0.08 and "English" in info.ic_reading
    assert 3.5 < info.entropy < 5 and info.entropy_reading == "text-like"
    assert abs(sum(info.letter_freq.values()) - 100) < 1e-6
    assert info.guesses and sum(info.byte_counts) == info.size


def test_insight_on_binary_and_encodings():
    blob = os.urandom(4096).hex()
    info = insight.analyse(blob, encoding="hex")
    assert info.encoding == "hex" and info.size == 4096 and not info.texty
    assert info.entropy > 7.5 and len(info.entropy_series) > 2


def test_insight_matches_the_analysis_commands_by_default():
    """Undecoded unless asked, exactly like `aesop identify` / `entropy`."""
    info = insight.analyse("5f4dcc3b5aa765d61d8327deb882cf99")
    assert info.size == 32 and info.encoding == "raw" and info.sniffed == "hex"
    assert info.guesses[0].kind == "hash"
    info = insight.analyse("aGVsbG8gd29ybGQ=")
    assert info.size == 16 and info.sniffed == "base64"
    assert insight.analyse("plain words").sniffed == ""


def test_insight_never_raises():
    assert insight.analyse("").empty and insight.analyse("   \n").empty
    assert "ValueError" in insight.analyse("zz", encoding="hex").error
    assert insight.analyse(None, file="/no/such/file").error


def test_insight_reads_files(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(bytes(range(256)) * 8)
    info = insight.analyse("ignored", file=str(p))
    assert info.size == 2048 and info.source == f"file:{p}"
    assert info.byte_counts == [8] * 256


# --------------------------------------------------------------------------- #
# worker + runner (real subprocess, no display needed)
# --------------------------------------------------------------------------- #
class Session:
    def __init__(self):
        self.events: "queue.Queue[dict]" = queue.Queue()
        self.runner = Runner(self.events.put)

    def run(self, argv, timeout=60):
        rid = self.runner.submit(argv)
        return self.collect(rid, timeout)

    def collect(self, rid, timeout=60):
        got, deadline = [], time.time() + timeout
        while True:
            ev = self.events.get(timeout=max(0.1, deadline - time.time()))
            if ev.get("id") != rid:
                continue
            got.append(ev)
            if ev["kind"] == "done":
                return got


@pytest.fixture(scope="module")
def session():
    s = Session()
    yield s
    s.runner.close()


def test_worker_runs_a_command(session):
    events = session.run(["caesar", "Wkh txlfn eurzq ira"])
    assert events[0]["kind"] == "start" and events[-1]["code"] == 0
    raw = [e for e in events if e["kind"] == "raw"]
    assert raw and raw[0]["text"] == "The quick brown fox"
    assert any(e["kind"] == "table" for e in events)
    assert not session.runner.busy


def test_worker_accepts_aliases_and_meta_commands(session):
    assert session.run(["rot", "-n", "13", "Uryyb"])[1]["text"] == "Hello"
    kinds = {e["kind"] for e in session.run(["manual", "caesar"])}
    assert "markdown" in kinds
    assert session.run(["list"])[-1]["code"] == 0
    assert session.run(["repl"])[-1]["code"] == 2


def test_worker_reports_usage_errors_without_dying(session):
    events = session.run(["caesar", "--no-such-flag"])
    assert events[-1]["code"] == 2
    assert "unrecognized arguments" in events_to_text(events)
    events = session.run(["caesar", "-h"])
    assert events[-1]["code"] == 0 and "usage: aesop caesar" in events_to_text(events)
    assert session.run(["rot47", "hello"])[-1]["code"] == 0      # still alive


def test_worker_has_no_stdin_to_wait_on(session):
    """With no input a handler must fail fast, not block reading stdin."""
    events = session.run(["identify"], timeout=10)
    assert events[-1]["code"] != 0 and "no input" in events_to_text(events)
    events = session.run(["prng", "--mt"], timeout=10)
    assert events[-1]["code"] != 0 and "no numbers given" in events_to_text(events)


def test_worker_handles_binary_and_unicode_output(session):
    events = session.run(["hex", "-d", "00ff41e9"])
    assert events[-1]["code"] == 0
    events = session.run(["b64", "-e", "raw", "héllo → wörld"])
    assert events[-1]["code"] == 0 and events[1]["kind"] == "raw"


def test_runner_refuses_overlapping_runs_and_can_cancel(session):
    slow = ["playfair", "--restarts", "500", "--iters", "90000",
            "BMODZBXDNABEKUDMUIXMMOUVIF" * 6]
    rid = session.runner.submit(slow)
    assert session.runner.busy
    with pytest.raises(RuntimeError):
        session.runner.submit(["rot47", "x"])
    time.sleep(0.5)
    started = time.time()
    assert session.runner.cancel() is True
    assert time.time() - started < 5
    done = session.collect(rid)[-1]
    assert done["code"] == CANCELLED and done["cancelled"]
    assert session.runner.cancel() is False
    # a fresh worker takes over transparently
    assert session.run(["rot47", "hello"])[1]["text"] == "96==@"


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #
def test_cli_knows_the_gui_command():
    args = cli.build_parser().parse_args(["gui", "caesar", "--theme", "light"])
    assert (args._meta, args.start, args.theme) == ("gui", "caesar", "light")
    assert cli.build_parser().parse_args(["workbench"])._meta == "gui"


def test_cli_gui_rejects_unknown_start_command(capsys):
    assert cli.main(["gui", "definitely-not-a-command"]) == 2


def test_gui_reports_missing_display(monkeypatch, capsys):
    pytest.importorskip("tkinter")
    from aesop.gui import run_gui
    monkeypatch.setenv("DISPLAY", ":63999")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    if os.name != "posix" or os.uname().sysname == "Darwin":
        pytest.skip("display selection is X11-specific")
    assert run_gui() == 1
    assert "could not open a window" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The window (needs Tk and a display)
# --------------------------------------------------------------------------- #
def _root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display: {exc}")
    root.withdraw()              # never flash a window during the test run
    return root


@pytest.fixture()
def app(tmp_path):
    root = _root()
    from aesop.gui.app import Workbench
    wb = Workbench(root, prefs_path=str(tmp_path / "gui.json"), command="caesar")
    root.update()
    yield wb
    wb.close()


def _settle(wb, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        wb.root.update()
        time.sleep(0.01)
        if not wb.runner.busy and wb.run_record is None and wb.events.empty():
            wb.root.update()
            return
    pytest.fail("the run did not finish")


def _pump(wb, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        wb.root.update()
        time.sleep(0.01)


def test_window_lists_every_command(app):
    shown = [c for g in app.tree.get_children() for c in app.tree.get_children(g)]
    assert sorted(shown) == sorted(REGISTRY)
    app.search.set_value("vigen")
    app.root.update()
    assert app._visible == ["vigenere"]
    app._pick_first()
    assert app.cmd.name == "vigenere"


def test_window_runs_a_command_and_chains_the_result(app):
    app.set_input("Wkh txlfn eurzq ira")
    assert app.argv() == ["caesar", "Wkh txlfn eurzq ira"]
    app.run()
    _settle(app)
    assert app.shown.code == 0 and app.shown.result == "The quick brown fox"
    text = app.output.get("1.0", "end")
    assert "$ aesop caesar 'Wkh txlfn eurzq ira'" in text
    assert "The quick brown fox" in text and "candidates" in text
    assert len(app.history.runs) == 1

    app.select_command("b64")
    assert app.get_input() == "Wkh txlfn eurzq ira"      # the workspace persists
    app.use_result()
    app.run()
    _settle(app)
    assert app.shown.result == "VGhlIHF1aWNrIGJyb3duIGZveA=="


def test_window_form_follows_the_command(app):
    app.select_command("rsa")
    assert not app._has("input")
    assert "n" in app.form.values() and "file" in app.form.values()
    app.select_command("pcap")
    app.run()
    assert "CAPTURE" in app.status_text.cget("text") and not app.runner.busy
    app.select_command("caesar")
    assert set(app.form.values()) == {"shift", "encode", "all", "top"}
    app.form.set_values({"all": True, "top": "9"})
    app.set_input("Uryyb")
    assert app.argv() == ["caesar", "--all", "--top", "9", "Uryyb"]


def test_window_prefers_the_file_over_the_text(app, tmp_path):
    p = tmp_path / "c.txt"
    p.write_text("Wkh txlfn eurzq ira")
    app.set_input("ignored")
    app.file.set(str(p))
    assert app.argv() == ["caesar", "--file", str(p)]
    app.run()
    _settle(app)
    assert app.shown.result == "The quick brown fox"
    app.set_input("Uryyb")                   # choosing text clears the file
    assert app.file.get() == "" and app.argv() == ["caesar", "Uryyb"]


def test_window_loads_examples_and_manual_links(app):
    assert app.load_example("echo 'Fdhvdu flskhu' | aesop caesar --top 2")
    assert app.cmd.name == "caesar" and app.get_input() == "Fdhvdu flskhu"
    assert app.form.values()["top"] == "2"
    assert app.load_example("aesop vig -k LEMON --encode 'Attack at dawn'")
    assert app.cmd.name == "vigenere"
    assert app.argv() == ["vigenere", "--key", "LEMON", "--encode", "Attack at dawn"]
    assert not app.load_example("cat x | aesop xor")

    assert app.resolve_code("aesop manual scoring") is not None
    assert app.resolve_code("$ aesop caesar --all 'Uryyb Jbeyq'") is not None
    assert app.resolve_code("c = (p + k) mod 26") is None
    app.resolve_code("aesop manual scoring")()
    assert app.manual.slug == "scoring"
    assert "Scoring" in app.manual.page.text.get("1.0", "2.0")


def test_window_shows_every_manual_page(app):
    for slug in load_manual():
        assert app.manual.show(slug), slug
        assert app.manual.page.text.get("1.0", "end").strip(), slug


def test_window_command_bar_history_and_restore(app):
    app.bar.set_value("aesop vigenere -k LEMON --encode 'Attack at dawn'")
    app._on_bar(None)
    _settle(app)
    assert app.shown.result == "Lxfopv ef rnhr"
    app.bar.set_value("caesar --bogus")
    app._on_bar(None)
    _settle(app)
    assert app.shown.code == 2
    assert [r.outcome for r in app.history.runs] == ["ok", "exit 2"]

    app.select_command("hex")
    app.restore(app.history.runs[0])
    assert app.cmd.name == "vigenere" and app.get_input() == "Attack at dawn"
    assert "Lxfopv ef rnhr" in app.output.get("1.0", "end")
    assert "Lxfopv ef rnhr" in app.output_text()


def test_window_can_stop_a_long_run(app):
    app.select_command("playfair")
    app.set_input("BMODZBXDNABEKUDMUIXMMOUVIF" * 6)
    app.form.set_values({"restarts": "500", "iters": "90000"})
    app.run()
    _pump(app, 0.6)
    assert app.runner.busy and str(app.stop_button.cget("state")) == "normal"
    app.stop()
    _settle(app)
    assert app.shown.cancelled and app.shown.outcome == "stopped"
    assert str(app.run_button.cget("state")) == "normal"


def test_window_table_cells_map_back_to_full_values(app):
    long_text = "Uryyb Jbeyq, guvf vf n irel ybat frperg zrffntr " * 4
    app.set_input(long_text)
    app.form.set_values({"all": True})
    app.run()
    _settle(app)
    table = app.output._tables[0]
    assert table["count"] == 26 and table["columns"] == ["shift", "score", "plaintext"]
    line = app.output.get(f"{table['first']}.0", f"{table['first']}.end")
    assert line.split()[0] == table["rows"][0][0][0]


def test_window_inspector_and_themes(app):
    app.set_input("It was a bright cold day in April, and the clocks were striking "
                  "thirteen. " * 3)
    app.refresh_inspector()
    assert app.inspector.letters.has_data()
    assert "bytes" in app.inspector.length.value.cget("text")
    app.set_input(os.urandom(2048).hex())
    app.encoding.set("hex")
    app.refresh_inspector()
    assert app.inspector.bytes.has_data() and app.inspector.entropy_chart.has_data()
    assert app.inspector.entropy.value.cget("text").startswith("7.")
    for name in ("light", "dark"):
        app.set_theme(name)
        app.root.update()
        assert app.theme.name == name
        assert app.output.cget("background") == app.theme.palette.surface


def test_window_remembers_preferences(tmp_path):
    root = _root()
    from aesop.gui.app import Workbench
    path = str(tmp_path / "nested" / "gui.json")
    wb = Workbench(root, prefs_path=path, command="xor")
    wb.set_theme("light")
    wb.close()
    wb = Workbench(_root(), prefs_path=path)
    try:
        assert wb.cmd.name == "xor" and wb.theme.name == "light"
    finally:
        wb.close()
