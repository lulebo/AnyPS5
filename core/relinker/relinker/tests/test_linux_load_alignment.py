"""Check that a Linux relink keeps the image base aligned to the guest segment alignment and refuses a PT_LOAD whose file offset is not congruent to its address modulo the page, which the Windows and macOS outputs still convert."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

PT_LOAD = 1
PT_SCE_VERSION = 0x6FFFFF01


def fixture():
    image = bytearray(0x8000)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16,
                     3, 62, 1, 0x4000, 64, 0, 0, 64, 56, 6, 64, 0, 0)
    image[0x4000:0x4006] = b"\xb8\x2a\x00\x00\x00\xc3"
    tags = [(5, 0x600), (10, 1), (6, 0x620), (11, 24), (7, 0x700), (8, 0), (9, 24), (0, 0)]
    struct.pack_into("<IIQQQQQQ", image, 64,
                     PT_LOAD, 5, 0x4000, 0, 0, 0x1000, 0x1000, 0x4000)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     2, 6, 0x600 + 0x4000, 0x600, 0x600, len(tags) * 16, len(tags) * 16, 8)
    for index in range(2, 6):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, PT_SCE_VERSION, 0, 0, 0, 0, 0, 0, 1)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x4600 + index * 16, *tag)
    return image


def misplaced():
    image = fixture()
    struct.pack_into("<Q", image, 24, 0x800)
    struct.pack_into("<QQ", image, 64 + 16, 0x800, 0x800)
    struct.pack_into("<QQ", image, 120 + 16, 0xE00, 0xE00)
    for index in (0, 2, 4):
        address, = struct.unpack_from("<Q", image, 0x4600 + index * 16 + 8)
        struct.pack_into("<Q", image, 0x4600 + index * 16 + 8, address + 0x800)
    return image


def loads(elf):
    phoff, = struct.unpack_from("<Q", elf, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", elf, 0x36)
    headers = [struct.unpack_from("<IIQQQQQQ", elf, phoff + index * phentsize) for index in range(phnum)]
    return [header for header in headers if header[0] == PT_LOAD]


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-align-") as directory:
        source = Path(directory) / "input.elf"
        output = Path(directory) / "output.elf"
        source.write_bytes(fixture())
        missing = subprocess.run([str(relinker), str(source), str(output)], capture_output=True, text=True, timeout=20)
        assert missing.returncode != 0 and not output.exists(), missing
        assert "sce_module/*.prx was not found" in missing.stderr, missing.stderr
        assert "--skip-sce-module to disable guest module processing" in missing.stderr, missing.stderr
        result = subprocess.run([str(relinker), "--skip-sce-module", str(source), str(output)], capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise AssertionError((result.returncode, result.stdout, result.stderr))
        segments = loads(output.read_bytes())
        first = segments[0]
        alignment = max(segment[7] for segment in segments)
        if alignment != 0x4000 or first[3] % alignment != 0 or first[7] != alignment:
            raise AssertionError(("first PT_LOAD is not aligned to the largest segment alignment", segments))
        assert "  |-- output.elf\n  |-- libs/\n        |-- *.prx (system libraries)\n  |-- app0/" in result.stdout, result.stdout

        malformed = fixture()
        struct.pack_into("<Q", malformed, 64 + 40, 0x0fff)
        source.write_bytes(malformed)
        output.unlink()
        result = subprocess.run([str(relinker), "--skip-sce-module", str(source), str(output)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 2 and "PT_LOAD file size exceeds memory size" in result.stderr and not output.exists(), result

        source.write_bytes(fixture())
        named_exe = Path(directory) / "linux.EXE"
        warning = subprocess.run([str(relinker), "--skip-sce-module", str(source), str(named_exe)], capture_output=True, text=True, timeout=20)
        assert warning.returncode == 0, (warning.stdout, warning.stderr)
        assert "--windows was not specified" in warning.stderr, warning.stderr
        assert named_exe.read_bytes().startswith(b"\x7fELF"), "The filename must not select the output format"

        source.write_bytes(misplaced())
        for options in ((), ("--lazy-binding",)):
            result = subprocess.run([str(relinker), "--skip-sce-module", *options, str(source), str(output)],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 2 and not output.exists(), (options, result)
            assert "PT_LOAD at 0x800 has file offset 0x4000, which is not congruent to its address modulo 0x1000" in result.stderr, (options, result.stderr)
        for option, name in (("--windows", "misplaced.exe"), ("--macos", "misplaced")):
            converted = Path(directory) / name
            result = subprocess.run([str(relinker), "--skip-sce-module", option, str(source), str(converted)],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 0 and converted.exists(), (option, result.stdout, result.stderr)
    print("Linux load alignment test passed")


if __name__ == "__main__":
    main()
