# bip39_wordlist_generator.py
import requests

# URLs for BIP-39 wordlists in different languages
BIP39_WORDLIST_URLS = {
    "english": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt",
    "chinese_simplified": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/chinese_simplified.txt",
    "chinese_traditional": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/chinese_traditional.txt",
    "czech": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/czech.txt",
    "french": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/french.txt",
    "italian": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/italian.txt",
    "japanese": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/japanese.txt",
    "korean": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/korean.txt",
    "portuguese": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/portuguese.txt",
    "spanish": "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/spanish.txt"
}


def fetch_wordlist(url):
    """Fetch the wordlist from the URL."""
    response = requests.get(url)
    response.raise_for_status()
    return response.text.strip().split("\n")

def generate_header(wordlist, output_file, language):
    """Generate the C++ header file."""
    header_guard = f"BIP39_WORDLIST_{language.upper()}_H"
    array_name = f"BIP39_WORDLIST_{language.upper()}"
    with open(output_file, "w", encoding="utf-8") as f:  # Specify UTF-8 encoding
        f.write(f"// Auto-generated BIP-39 {language.capitalize()} wordlist\n")
        f.write(f"#pragma once\n")
        f.write("#include <array>\n#include <string>\n\n")
        f.write(f"constexpr std::array<const char*, 2048> {array_name} = {{\n")
        f.write(",\n".join([f'    "{word}"' for word in wordlist]))
        f.write("\n};\n\n")

if __name__ == "__main__":
    for language, url in BIP39_WORDLIST_URLS.items():
        print(f"Fetching BIP-39 {language.capitalize()} wordlist...")
        try:
            wordlist = fetch_wordlist(url)
            output_file = f"bip39_wordlist_{language}.h"
            print(f"Generating header file: {output_file}")
            generate_header(wordlist, output_file, language)
            print(f"{language.capitalize()} header file generated successfully!")
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch {language.capitalize()} wordlist: {e}")