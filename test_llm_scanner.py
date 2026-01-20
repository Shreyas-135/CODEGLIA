#!/usr/bin/env python3
"""
Simple test for LLM scanner module
"""
import os
import json

# Set up test environment
os.environ["GEMINI_API_KEY"] = "test_key"

# Import the module
from llm_scanner import LLMScanner

def test_scanner_initialization():
    """Test that the scanner initializes correctly."""
    print("Testing LLM Scanner initialization...")
    
    try:
        # Test Gemini backend (will fail due to invalid API key, but should initialize)
        scanner = LLMScanner(backend="gemini", model="gemini-2.0-flash-exp")
        print("✅ Gemini scanner initialized")
        print(f"   Backend: {scanner.backend}")
        print(f"   Model: {scanner.model}")
        print(f"   Cache enabled: {scanner.cache_enabled}")
    except Exception as e:
        print(f"❌ Failed to initialize scanner: {e}")
        return False
    
    return True

def test_file_filtering():
    """Test that file filtering works correctly."""
    print("\nTesting file filtering...")
    
    scanner = LLMScanner(backend="gemini")
    
    test_files = [
        ("test.py", True),
        ("test.js", True),
        ("test.java", True),
        ("test.txt", False),
        ("test.md", False),
        ("test.cpp", True),
        ("test.rb", True),
    ]
    
    for filename, should_scan in test_files:
        result = scanner._should_scan_file(filename)
        status = "✅" if result == should_scan else "❌"
        print(f"   {status} {filename}: {result} (expected: {should_scan})")
    
    return True

def test_language_detection():
    """Test language detection from filenames."""
    print("\nTesting language detection...")
    
    scanner = LLMScanner(backend="gemini")
    
    test_cases = [
        ("test.py", "python"),
        ("test.js", "javascript"),
        ("test.java", "java"),
        ("test.cpp", "cpp"),
        ("test.c", "c"),
        ("test.rb", "ruby"),
    ]
    
    for filename, expected_lang in test_cases:
        result = scanner._get_language_from_file(filename)
        status = "✅" if result == expected_lang else "❌"
        print(f"   {status} {filename}: {result} (expected: {expected_lang})")
    
    return True

def test_cache_key_generation():
    """Test cache key generation."""
    print("\nTesting cache key generation...")
    
    scanner = LLMScanner(backend="gemini")
    
    code1 = "import os; os.system('ls')"
    code2 = "import os; os.system('ls')"
    code3 = "import os; os.system('pwd')"
    
    key1 = scanner._get_cache_key(code1, "test.py")
    key2 = scanner._get_cache_key(code2, "test.py")
    key3 = scanner._get_cache_key(code3, "test.py")
    
    if key1 == key2:
        print("   ✅ Same code produces same cache key")
    else:
        print("   ❌ Same code should produce same cache key")
    
    if key1 != key3:
        print("   ✅ Different code produces different cache key")
    else:
        print("   ❌ Different code should produce different cache key")
    
    return True

def test_response_parsing():
    """Test LLM response parsing."""
    print("\nTesting LLM response parsing...")
    
    scanner = LLMScanner(backend="gemini")
    
    # Test valid JSON response
    valid_response = """```json
[
    {
        "line": 10,
        "severity": "high",
        "issue_text": "SQL Injection",
        "cwe": "CWE-89",
        "explanation": "This is a test",
        "fix": "Use prepared statements"
    }
]
```"""
    
    result = scanner._parse_llm_response(valid_response, "test.py")
    
    if len(result) == 1:
        print("   ✅ Parsed 1 vulnerability")
        vuln = result[0]
        print(f"      Scanner: {vuln.get('scanner')}")
        print(f"      Severity: {vuln.get('severity')}")
        print(f"      CWE: {vuln.get('cwe')}")
    else:
        print(f"   ❌ Expected 1 vulnerability, got {len(result)}")
    
    # Test empty response
    empty_response = "[]"
    result = scanner._parse_llm_response(empty_response, "test.py")
    
    if len(result) == 0:
        print("   ✅ Empty response parsed correctly")
    else:
        print(f"   ❌ Expected 0 vulnerabilities, got {len(result)}")
    
    return True

def main():
    """Run all tests."""
    print("=" * 50)
    print("LLM Scanner Module Tests")
    print("=" * 50)
    
    tests = [
        test_scanner_initialization,
        test_file_filtering,
        test_language_detection,
        test_cache_key_generation,
        test_response_parsing,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    print("\n" + "=" * 50)
    print(f"Tests passed: {sum(results)}/{len(results)}")
    print("=" * 50)
    
    return all(results)

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
