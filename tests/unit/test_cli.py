import pytest

from corsone import __version__
from corsone.cli import _write_output, build_parser, main


def test_parser_defaults() -> None:
    parser = build_parser()
    args = parser.parse_args(["-u", "https://example.com"])
    assert args.method == "GET"
    assert args.workers == 5
    assert args.timeout == 10


def test_main_version(capsys) -> None:
    exit_code = main(["--version"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"CorsOne {__version__}" in captured.out


def test_write_output_allows_file_in_current_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    _write_output("report", "result.txt")

    assert (tmp_path / "result.txt").read_text(encoding="utf-8") == "report"


@pytest.mark.parametrize("path", ["../outside.txt", str(__file__)])
def test_write_output_rejects_path_outside_current_directory(tmp_path, monkeypatch, path) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="inside the current working directory"):
        _write_output("report", path)
