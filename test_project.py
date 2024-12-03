from project import File, Strings, Hash, VirusTotal
import pytest


def test_hash():

    # Test with a valid file
    file = File("HxD.exe")
    hash_value = Hash.extract_hash(file.filename)
    assert hash_value == True

    # Test with a non-existing file
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        file = File("not_existing_file")
        Hash.calculate(file.filename)
    assert pytest_wrapped_e.type == SystemExit


def test_strings():

    file = File("HxD.exe").filename

    # Strings extraction without specified output name
    assert Strings.extract_strings(file) == True

    # Strings extraction with specified output name
    assert Strings.extract_strings(file, "malware_strings.txt") == True


def test_input_file():

    # File exists, and has "MZ" signature
    file = File("HxD.exe")
    assert file.pe_validate("HxD.exe") == True

    # Not existing file
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        file = File("not_existing_file")
    assert pytest_wrapped_e.type == SystemExit

    # Existing file without PE signature
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        file = File("api")
    assert pytest_wrapped_e.type == SystemExit
