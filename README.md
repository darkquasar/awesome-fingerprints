# Awesome Fingerprints
This repo is a curated collection of resources, tools, and techniques for generating, analyzing, and comparing fingerprints (hashes) of digital artifacts.

# Table of Contents

- [But what are fingerprints anyway?](#but-what-are-fingerprints-anyway)
    - [Why should we care about fingerprints in Cybersecurity?](#why-should-we-care-about-fingerprints-in-cybersecurity)
- [Digital Fingerprints](#digital-fingerprints)
- [Useful References](#useful-references)
- [Tools](#tools)

# But what are fingerprints anyway?

Fingerprinting is an old data analysis technique that dates back to the [19th century](https://archiveshub.jisc.ac.uk/features/forensics.shtml). Fingerprinting involves collecting and analyzing unique characteristics (or "features") of an entity (such as a person, device, or digital object) to create a distinctive identifier or "fingerprint". This fingerprint serves as a concise representation of the entity's unique traits and is used for various purposes, including identification, authentication, tracking, and anomaly detection.

At its core, fingerprinting is a data reduction technique that enables fast pattern recognition for scalable identification of uniqueness in datasets (whether physical or digital) and fuzzy clustering. Fingerprinting techniques are widely used in fields like cybersecurity, forensics, biometrics, and even marketing.

## Why should we care about fingerprints in Cybersecurity?

Fingerprinting is crucial in our field because it is a powerful data analysis technique. This technique is essential for:

- **Intrusion Prevention**: by creating fingerprints of known threats (like malware signatures or hacker tools), security systems can quickly identify and block them before they cause damage.
- **Authentication and Access Control**: fingerprinting can verify the identity of users or devices attempting to access a system, ensuring that only authorized entities are granted entry.
- **Anomaly Detection and Detection Engineering**: by comparing fingerprints over time, unusual behavior or deviations from normal patterns can be detected, signaling potential security breaches or unauthorized activities.
- **Threat Hunting and Threat Intelligence**: fingerprints can be used to proactively expand the graph of attacker infrastructure and combine datasets in unique ways for data clustering and analysis. By identifying unique characteristics associated with known threats, security teams can uncover hidden threats that may have evaded traditional security measures.
- **Forensic Investigations**: In the event of a security incident, fingerprints can be used to grok evidence and create unique hashes to ensure chain of custody.

There are of course many more use-cases for each of the categories above, I'm just lazy and don't want to list them all right here :)

# Digital Fingerprints

## File Fingerprints

### md5

The MD5 (Message-Digest Algorithm) is a widely used hash function producing a 128-bit hash value. MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4, and was specified in 1992 as RFC 1321.

- Ref: [MD5 Wiki](https://www.wikiwand.com/en/MD5)


### SHA (Secure Hash Algorithms) [SHA-0, SHA-1, SHA-2, SHA3]

The Secure Hash Algorithms are a family of cryptographic hash functions published by the National Institute of Standards and Technology (NIST) as a U.S. Federal Information Processing Standard (FIPS). Common hashes used in cybersecurity are **SHA-256** and **SHA-512**.

  - Ref: [Secure Hash Algorithms](https://www.wikiwand.com/en/Secure_Hash_Algorithms)

### vhash

VirusTotal custom similarity clustering algorithm value, based on a simple structural feature hash, it allows you to find similar files.

  - Ref: [VT Files](https://docs.virustotal.com/reference/files).

### authentihash

a sha256 hash [used by Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) to verify that the relevant sections of a PE image file have not been altered. The authentihash is used within Microsoft's Authenticode. Try it yourself with PowerShell: `Get-AuthenticodeSignature C:\Windows\bfsvc.exe`

### pehash

A non cryptographic, fast to calculate hash function for binaries in the Portable Executable format that transforms structural information about a sample into a hash value. There is not a single interpretation of PEHASH, over the last decade, researchers and tools have modified or extended the original pehash algorithm to incorporate additional features or focus on specific aspects of PE files. These variations may include different combinations of sections to hash, different hashing algorithms, or different ways of combining the hash values.

  - Ref:
      - https://www.usenix.org/legacy/events/leet09/tech/full_papers/wicherski/wicherski.pdf
      - https://github.com/knowmalware/pehash

### SSDEEP

SSDEEP is a "context triggered piecewise hash" or fuzzy hash algorithm designed to compare similar but not identical files. Unlike traditional cryptographic hashes like MD5 or SHA256, which produce drastically different outputs even with minor changes to the input, SSDEEP aims to generate similar hashes for files with minor modifications SSDEEP can detect similarities even when files have been modified, such as by adding or removing content, changing formatting, or applying compression.

  - Uses: asdf
  - Ref: 

### Imphash

TBD

### ImpFuzzy

TBD


## Website Favicon and other Icon Hashes

### VirusTotal raw_md5

VirusTotal icon's MD5 hash.

### VirusTotal dhash

VirusTotal icon's difference hash. Its a visual fuzzy hash that can be used to search for files with similar icons using the [/intelligence/search](https://docs.virustotal.com/reference/intelligence-search) endpoint.

## Other Data Hashes:

### Locality Sensitive Hashing

*Locality Sensitive Hashing is a clever technique that uses special hash functions to significantly speed up the process of finding similar pairs in large datasets*. It's a powerful tool in many areas of data analysis and machine learning. Imagine you have a massive dataset containing a huge number (N) of items. These could be documents, images, or any other kind of data. Your goal is to find pairs of items that are similar to each other. This is a common task in many fields: eecommendation systems, duplicate detection, near-duplicate image search, anomaly detection. The most straightforward way to find similar pairs is to compare every single item to every other item. This is called the "brute force" method. The problem is that the number of comparisons you need to make grows incredibly fast as your dataset gets larger. Specifically, it grows at a rate of `N²/2`, which is a quadratic relationship `(O(N²))`. LSH comes to the rescue by offering a much more efficient way to find similar pairs by using special hash functions that are designed to *put similar items into the same "bucket" with a high probability*. 

- Ref: [how to find similar items in a large dataset](https://towardsdatascience.com/locality-sensitive-hashing-how-to-find-similar-items-in-a-large-set-with-precision-d907c52b05fc)

### Jaccard Similarity

Jaccard is a metric used to measure the similarity between two sets. `Jaccard(A, B) = (A ∩ B) / (A ∪ B)`. The Jaccard similarity coefficient is calculated as the size of the intersection of the sets divided by the size of the union of the sets.

# Tools

- pestudio: TBD
- [pestudio-cli](https://github.com/KuechA/pestudio-cli): Python-based command-line tool to scan PE files for malicious patterns by checking VirusTotal, comparing against known malware signatures, inspecting libraries and resources, analyzing strings, and examining PE file structure. Additionally, we assess various suspicious values like high entropy, imphashes, and anomalies in entry-point address, sections, headers, and data, and optionally incorporate YARA rules if the library is installed.
- readpe: TBD
- [python-ssdeep](https://github.com/DinoTools/python-ssdeep): This is a straightforward Python wrapper for ssdeep by Jesse Kornblum, which is a library for computing context triggered piecewise hashes (CTPH). Also called fuzzy hashes, CTPH can match inputs that have homologies. Such inputs have sequences of identical bytes in the same order, although bytes in between these sequences may be different in both content and length.
- [hashdeep](https://github.com/jessek/hashdeep): This is md5deep, a set of cross-platform tools to compute hashes, or message digests, for any number of files while optionally recursively digging through the directory structure. It can also take a list of known hashes and display the filenames of input files whose hashes either do or do not match any of the known hashes. This version supports MD5, SHA-1, SHA-256, Tiger, and Whirlpool hashes.
- [hashit](https://github.com/boyter/hashit): A hash tool which can work like hashdeep or md5sum, sha1sum, etc... When you want to find the hash or hashes of a file quickly, cross platform using a single command.

# Useful References

- https://github.com/knowmalware/pehash: Compilation of peHash implementations. Several tools currently use a TotalHash-compatible implementation, however the malware analysis and research communities have not yet clearly chosen a winner. This modules provides a unified interface to all known peHash implementations.