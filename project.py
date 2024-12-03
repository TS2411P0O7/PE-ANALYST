import pefile
import sys
import subprocess
import hashlib
import vt
import re
import datetime
from colorama import Fore, Back, Style


def print_help():
    help_text = """
Usage: python project.py <file_path> [options]

Arguments:
  <file_path>   Path to the PE file to be analyzed.

Options:
  -h            Hash Extraction
                - Extracts the hash (MD5, SHA-1, SHA-256, SHA-512) of the provided file.
                - Usage:
                  - Without a specific hash algorithm: Displays all available hashes (MD5, SHA-1, SHA-256, SHA-512).
                    python project.py <file_path> -h
                  - With a specific hash algorithm: Displays the chosen hash (ie. MD5, SHA-1, SHA-256, SHA-512).
                    python project.py <file_path> -h <hash_algorithm>
                  Example: python project.py sample.exe -h MD5

  -s            Strings Extraction
                - Extracts printable strings from the provided file and saves them to a text file.
                - Usage:
                  - Without a specified output file: Saves strings to the default "strings.txt".
                    python project.py <file_path> -s
                  - With a specified output file: Saves strings to the specified file.
                    python project.py <file_path> -s <output_file_name>
                  Example: python project.py sample.exe -s custom_strings.txt

  -vt           VirusTotal Integration
                - Fetches and displays information from VirusTotal for the provided file hash.
                - Usage:
                  - Use -vt followed by -summary to get a summary of the VirusTotal analysis.
                    python project.py <file_path> -vt -summary
                  Example: python project.py sample.exe -vt -summary

  -p            PE Parsing
                - Extracts and displays information about the provided PE file.
                - Usage:
                  - Use -p followed by one of the following options to view detailed information:
                    - -peinfo   - General information and PE header
                    - -imports  - List of imported functions
                    - -exports  - List of exported resources
                  Example: python project.py sample.exe -p -peinfo

  Notes:
  - The script requires the `vt` (VirusTotal) Python client and the `strings` utility.
  - You need to have a valid API key for VirusTotal stored in a file named "api" in the same directory as the script.
  """
    print(help_text)


class PEfile:
    def __init__(self, f):
        self.PEfile = pefile.PE(f)


class File:
    def __init__(self, f):
        if self.pe_validate(f):
            self.filename = f
            return None

    def pe_validate(self, f):
        try:
            with open(f, "rb") as file:
                if not file.read(2).decode() == "MZ":
                    sys.exit("Invalid PE file")
                return True
        except FileNotFoundError:
            sys.exit(f"File '{f}' does not exist")


class Hash:
    @classmethod
    def extract_hash(self, f, checksum=None, s=None):
        hash = {
            "MD5": hashlib.md5,
            "SHA-1": hashlib.sha1,
            "SHA-256": hashlib.sha256,
            "SHA-512": hashlib.sha512,
        }
        print()
        if checksum in hash:
            with open(f, "rb") as f:
                hash_value = hash[checksum](f.read()).hexdigest()
                if s:
                    return hash_value
                else:
                    print(Fore.RED + "=" * 50 + Fore.RESET)
                    print(Fore.RED + f"{"HASH":^50}" + Fore.RESET)
                    print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                    print(f"{checksum.ljust(20, '.')} {hash_value}")
                    print()

        elif checksum == None:
            print(Fore.RED + "=" * 50 + Fore.RESET)
            print(Fore.RED + f"{"HASHES":^50}" + Fore.RESET)
            print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
            with open(f, "rb") as f:
                for c in hash:
                    print(f"{c.ljust(20, '.')} {hash[c](f.read()).hexdigest()}")
                    print()

                return True
        else:
            return False


class Strings:
    @classmethod
    def extract_strings(self, f, out_file="strings.txt"):
        with open(out_file, "w") as out_file:
            subprocess.run(["strings", f], stdout=out_file)
            return True

    def filter_strings(f="strings.txt"):
        url_pattern = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)"
        file_pattern = r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
        output_urls = []
        output_files = []
        with open("strings.txt", "r") as file:
            for line in file:
                url_match = re.search(url_pattern, line)
                file_match = re.search(file_pattern, line)
                if url_match:
                    output_urls.append(url_match.group(0))
                if file_match:
                    output_files.append(file_match.group(0))

            # REGEX matching
            if output_urls:
                print(Fore.RED + "=" * 50 + Fore.RESET)
                print(Fore.RED + f"{"FOUND URL'S":^50}" + Fore.RESET)
                print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                for e in output_urls:
                    print(e)
                print()

            if output_files:
                print(Fore.RED + "=" * 50 + Fore.RESET)
                print(Fore.RED + f"{"FOUND PATHS / FILES":^50}" + Fore.RESET)
                print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                for e in output_files:
                    print(e)
            print()


class VirusTotal:
    def __init__(self):
        try:
            with open("api", "r") as apikey:
                self.api_key = apikey.read()
            self.client = vt.Client(self.api_key.strip())
        except vt.error.APIError as e:
            print("Something went wrong.")

    def get_object(self, hash):
        try:
            return self.client.get_object(f"/files/{hash}")
        except vt.error.APIError as e:
            if "Wrong API key" in str(e):
                self.client.close()
                sys.exit("Invalid API KEY, please verify.")
            if "NotFoundError" in str(e):
                sys.exit("Invalid hash")
            else:
                sys.exit(str(e))

    def close(self):
        self.client.close()

    def get_score(self, analysis):

        print(Fore.RED + "=" * 50 + Fore.RESET)
        print(Fore.RED + f"{"VIRUSTOTAL SUMMARY":^50}" + Fore.RESET)
        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")

        # SCORING
        malicious_score = analysis.last_analysis_stats["malicious"]
        harmless_score = analysis.last_analysis_stats["harmless"]
        undetected_score = analysis.last_analysis_stats["undetected"]
        community_score = analysis.reputation
        engines_used = len(analysis.last_analysis_results)

        # ADDITIONAL DATA
        file_type = analysis.type_description
        file_size = analysis.size
        first_submission = analysis.first_submission_date
        last_analysis = analysis.last_analysis_date

        print(f"{'File type'.ljust(20, '.')} {file_type}")
        print(f"{'File size'.ljust(20, '.')} {file_size / (1024 * 1024):.2f} MB")
        print(f"{'First submission'.ljust(20, '.')} {first_submission}")
        print(f"{'Last analysis'.ljust(20, '.')} {last_analysis}")
        print()

        print("Detection stats: ")
        print(f"{'Malicious score'.ljust(20, '.')} {malicious_score}")
        print(f"{'Harmless score'.ljust(20, '.')} {harmless_score}")
        print(f"{'Undetected score'.ljust(20, '.')} {undetected_score}")
        print(f"{'Community score'.ljust(20, '.')} {community_score}")
        print(f"{'Engines used'.ljust(20, '.')} {engines_used}")


def main():

    if 2 <= len(sys.argv) <= 4:
        file = File(sys.argv[1]).filename
        if len(sys.argv) > 2:
            argument = sys.argv[2]
            if len(sys.argv) > 3:
                options = sys.argv[3]

            ### VIRUS TOTAL
        if len(sys.argv) == 4 and argument == "-vt":
            if options in ["-summary"]:
                try:
                    vtClient = VirusTotal()
                    object = vtClient.get_object(
                        Hash.extract_hash(file, "MD5", "silent")
                    )
                    vtClient.get_score(object)
                    vtClient.close()
                except FileNotFoundError:
                    sys.exit("API-KEY missing. Create 'api' file with key inside.")
            else:
                print_help()

            ### PARSING FILE
        if len(sys.argv) == 4 and argument == "-p":
            if options in ["-peinfo", "-imports", "-exports"]:
                fileinfo = PEfile(file)
                match (options):

                    case "-peinfo":

                        ### GENERAL INFORMATION
                        print()
                        print(Fore.RED + "=" * 50 + Fore.RESET)
                        print(Fore.RED + f"{"GENERAL INFORMATION":^50}" + Fore.RESET)
                        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                        print(f"{"Valid PE File:".ljust(20, ".")} Yes")
                        print(
                            f"{"Entry Point Address:".ljust(20, ".")} {hex(fileinfo.PEfile.OPTIONAL_HEADER.AddressOfEntryPoint)}"
                        )
                        print(
                            f"{"Compile Timestamp:".ljust(20, ".")} {datetime.datetime.fromtimestamp(fileinfo.PEfile.FILE_HEADER.TimeDateStamp)}"
                        )
                        print(
                            f"{"Image Base:".ljust(20, ".")} {hex(fileinfo.PEfile.OPTIONAL_HEADER.ImageBase)}"
                        )
                        print(
                            f"{"Section Alignment:".ljust(20, ".")} {hex(fileinfo.PEfile.OPTIONAL_HEADER.SectionAlignment)}"
                        )
                        print()

                        ### PE HEADER
                        print(Fore.RED + "=" * 50 + Fore.RESET)
                        print(Fore.RED + f"{"PE HEADER":^50}" + Fore.RESET)
                        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")

                        print(
                            f"{"Machine Type:".ljust(20, ".")} {hex(fileinfo.PEfile.FILE_HEADER.Machine)}"
                        )
                        print(
                            f"{"Number of Sections:".ljust(20, ".")} {fileinfo.PEfile.FILE_HEADER.NumberOfSections}"
                        )
                        print(
                            f"{"Characteristics:".ljust(20, ".")} {hex(fileinfo.PEfile.FILE_HEADER.Characteristics)}"
                        )
                        print(
                            f"{"Size of Image:".ljust(20, ".")} {hex(fileinfo.PEfile.OPTIONAL_HEADER.SizeOfImage)}"
                        )
                        print()

                        ### SECTIONS
                        print(Fore.RED + "=" * 50 + Fore.RESET)
                        print(Fore.RED + f"{"SECTIONS":^50}" + Fore.RESET)
                        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                        for section in fileinfo.PEfile.sections:
                            print(
                                Style.BRIGHT
                                + f"SECTION: {section.Name.decode().strip()}"
                                + Style.RESET_ALL
                            )
                            print()
                            print(
                                f"  {'Virtual Size:'.ljust(25, '.')} {hex(section.Misc_VirtualSize)}"
                            )
                            print(
                                f"  {'Raw Size:'.ljust(25, '.')} {hex(section.SizeOfRawData)}"
                            )
                            if section.get_entropy() > 6:
                                print(
                                    f"  {'Entropy:'.ljust(25, '.')} {Fore.RED}{section.get_entropy():.2f}{Fore.RESET}"
                                )
                            else:
                                print(
                                    f"  {'Entropy:'.ljust(25, '.')} {Fore.YELLOW}{section.get_entropy():.2f}{Fore.RESET}"
                                )
                            print(
                                f"  {'Characteristics:'.ljust(25, '.')} {hex(section.Characteristics)}"
                            )
                            print()
                            print()

                    case "-imports":
                        print()
                        print(Fore.RED + "=" * 50 + Fore.RESET)
                        print(Fore.RED + f"{"IMPORTS":^50}" + Fore.RESET)
                        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                        for i in fileinfo.PEfile.DIRECTORY_ENTRY_IMPORT:
                            for e in i.imports:
                                print(e.name.decode())

                    case "-exports":
                        print()
                        print(Fore.RED + "=" * 50 + Fore.RESET)
                        print(Fore.RED + f"{"EXPORTS":^50}" + Fore.RESET)
                        print(Fore.RED + "=" * 50 + Fore.RESET + "\n")
                        for i in fileinfo.PEfile.DIRECTORY_ENTRY_RESOURCE.entries:
                            if i.name:
                                print(i.name)
            else:
                print_help()
        if len(sys.argv) == 2:
            print_help()

            ### HASHES
        if 3 <= len(sys.argv) <= 4 and argument == "-h":

            # Without hash argument, display all
            if len(sys.argv) == 3:
                Hash.extract_hash(file)

            # With hash argument, display chosen
            if len(sys.argv) == 4:
                Hash.extract_hash(file, options)

        ### STRINGS

        if 3 <= len(sys.argv) <= 4 and argument in ["-s", "-sf"]:

            # Without string file output argument
            if len(sys.argv) == 3:
                Strings.extract_strings(file)
                print()
                print(f"Created strings file 'strings.txt'")
                print()
                if argument == "-sf":
                    Strings.filter_strings()

            # With string out_name argument
            if len(sys.argv) == 4:
                Strings.extract_strings(file, options)
                print()
                print(f"Created strings file '{options}'")
                print()
                if argument == "-sf":
                    Strings.filter_strings(options)

    else:
        print_help()


if __name__ == "__main__":
    main()
