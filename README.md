# Awesome Fingerprints
This repo is a curated collection of resources,  tools, and techniques for generating, analyzing, and comparing fingerprints (hashes) of digital artifacts.

# Table of Contents

- Digital Fingerprints
- Useful References
- Tools

# Digital Fingerprints

## File Fingerprints

- **md5**: The MD5 (Message-Digest Algorithm) is a widely used hash function producing a 128-bit hash value. MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4, and was specified in 1992 as RFC 1321.
    - Ref: [MD5 Wiki](https://www.wikiwand.com/en/MD5)
- **SHA (Secure Hash Algorithms) [SHA-0, SHA-1, SHA-2, SHA3]**: The Secure Hash Algorithms are a family of cryptographic hash functions published by the National Institute of Standards and Technology (NIST) as a U.S. Federal Information Processing Standard (FIPS). Common hashes used in cybersecurity are **SHA-256** and **SHA-512**.
    - Ref: [Secure Hash Algorithms](https://www.wikiwand.com/en/Secure_Hash_Algorithms)
- **vhash**: VirusTotal custom similarity clustering algorithm value, based on a simple structural feature hash, it allows you to find similar files.
    - Ref: [VT Files](https://docs.virustotal.com/reference/files).
- **authencode (AKA authentihash)**: a sha256 hash [used by Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) to verify that the relevant sections of a PE image file have not been altered. This specific type of hash is used by Microsoft AppLocker.
- **pehash**: A non cryptographic, fast to calculate hash function for binaries in the Portable Executable format that transforms structural information about a sample into a hash value. There is not a single interpretation of PEHASH, over the last decade, researchers and tools have modified or extended the original pehash algorithm to incorporate additional features or focus on specific aspects of PE files. These variations may include different combinations of sections to hash, different hashing algorithms, or different ways of combining the hash values.
    - Ref:
        - https://www.usenix.org/legacy/events/leet09/tech/full_papers/wicherski/wicherski.pdf
        - https://github.com/knowmalware/pehash
- **SSDEEP**: TBD
- **Imphash**: TBD
- **ImpFuzzy**: TBD


## Website Favicon and other Icon Hashes

- **VirusTotal raw_md5**: VirusTotal icon's MD5 hash.
- **VirusTotal dhash**: VirusTotal icon's difference hash. Its a visual fuzzy hash that can be used to search for files with similar icons using the [/intelligence/search](https://docs.virustotal.com/reference/intelligence-search) endpoint.

## Other Data Hashes:

- **Locality Sensitive Hashing**: TBD
    - Ref: [how to find similar items in a large dataset](https://towardsdatascience.com/locality-sensitive-hashing-how-to-find-similar-items-in-a-large-set-with-precision-d907c52b05fc)


# Useful References

- https://github.com/knowmalware/pehash: Compilation of peHash implementations. Several tools currently use a TotalHash-compatible implementation, however the malware analysis and research communities have not yet clearly chosen a winner. This modules provides a unified interface to all known peHash implementations.

# Tools

- pestudio: TBD
- readpe: TBD