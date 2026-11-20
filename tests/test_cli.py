import whydrop
from whydrop.cli import main


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"whydrop {whydrop.__version__}"
