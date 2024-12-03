# PE-ANALYST

## **Overview**

The project is designed to help users validate PE files, extract strings, calculate hashes, and check files against the VirusTotal database for potential malware or suspicious activity.

## **Features**

- **File Analysis**: Analyze PE files to extract useful information.
- **Strings Extraction**: Extract strings from a file and filter them to identify potential hidden data or malicious behavior.
- **Hash Calculation**: Calculate and compare currently most-used hashes of files.
- **VirusTotal Integration**: Check file hashes against the VirusTotal database to see if they are flagged as malicious.

## **Installation**

Install the necessary dependencies:

```
pip install -r requirements.txt
```


## **Usage**
### File Analysis

Perform various file analyses, such as validating a file's PE signature or examining its imports and exports.

Example:
```
> python project.py <filename> -p -peinfo
```

Output:
```
==================================================
               GENERAL INFORMATION                
==================================================

Valid PE File:...... Yes
Entry Point Address: 0x1181c
Compile Timestamp:.. 2018-06-14 15:27:46
Image Base:......... 0x400000
Section Alignment:.. 0x1000

==================================================
                    PE HEADER                     
==================================================

Machine Type:....... 0x14c
Number of Sections:. 8
Characteristics:.... 0x818f
Size of Image:...... 0x28000

==================================================
                     SECTIONS                     
==================================================

SECTION: .text

  Virtual Size:............ 0xf25c
  Raw Size:................ 0xf400
  Entropy:................. 6.38
  Characteristics:......... 0x60000020

SECTION: .data

  Virtual Size:............ 0xc8c
  Raw Size:................ 0xe00
  Entropy:................. 2.30
  Characteristics:......... 0xc0000040
  
SECTION: .rsrc

  Virtual Size:............ 0xb200
  Raw Size:................ 0xb200
  Entropy:................. 4.14
  Characteristics:......... 0x40000040
```

To check imports or exports you can use:
```
> python project.py <filename> -p -imports
> python project.py <filename> -p -exports
```

### Hash Extraction

Calculate file hashes, including MD5, SHA-1, SHA-256, and SHA-512.

Example:
```
> python project.py <filename> -h
```

Output:
```
==================================================
                      HASHES                      
==================================================

MD5................. 4f9e75a41d02666cd5cc86bd33a578fe

SHA-1............... da39a3ee5e6b4b0d3255bfef95601890afd80709

SHA-256............. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

SHA-512............. cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
```

You can also use it for a specific checksum like ie. MD5:
```
> python project.py <filename> -h MD5
```

Output:
```
==================================================
                      HASH                      
==================================================

MD5................. 4f9e75a41d02666cd5cc86bd33a578fe
```

### VirusTotal Integration

Check a file hash against the VirusTotal database to identify potential threats.

**Setup**: Register at [VirusTotal](https://www.virustotal.com) to get a free API key. Save the key in a file named `api` in the project's root directory.

```
> python project.py <filename> -vt -summary
```

Output:
```
==================================================
                VIRUSTOTAL SUMMARY                
==================================================

File type........... Win32 EXE
File size........... 3.29 MB
First submission.... 2021-02-10 21:48:38
Last analysis....... 2024-12-03 07:54:07

Detection stats: 
Malicious score..... 0
Harmless score...... 0
Undetected score.... 72
Community score..... 79
Engines used........ 76
```

### Strings Extraction and Filtering

Extract ASCII and Unicode strings from a file to analyze hidden or hardcoded data such as URLs, file paths, and filenames.

Extract all strings:
```
> python project.py <filename> -s
```


Save extracted strings to a custom file:
```
> python project.py <filename> -s <output>
```


Extract and filter for suspicious URLs, paths, or filenames:

```
> python project.py <filename> -sf
```

```
> python project.py <filename> -sf <output>
```

Output:
```
==================================================
                   FOUND URL'S                    
==================================================

http://schemas.microsoft.com/SMI/2005/WindowsSettings

==================================================
               FOUND PATHS / FILES                
==================================================

C:\mal.dll
kerne132.dll
```


