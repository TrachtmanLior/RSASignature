#!/usr/bin/env python3
"""
Test file for RSA PKCS#1 v1.5 signature verification using NIST test vectors.
Parses and runs test cases from SigGen15_186-3.txt.
"""

import sys
import os
import re
from typing import Dict, List, Tuple, Optional

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rsasignature.rsa import RSA


class NISTTestParser:
    """Parser for NIST RSA signature test vectors."""
    
    def __init__(self, test_file: str = "SigGen15_186-3.txt"):
        self.test_file = test_file
        self.test_cases = []
        
    def parse_file(self) -> List[Dict]:
        """Parse the NIST test vector file and extract test cases."""
        try:
            with open(self.test_file, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: Test file '{self.test_file}' not found.")
            return []
        
        # Split into sections by [mod = ...]
        sections = re.split(r'\[mod = \d+\]', content)[1:]  # Skip header
        
        test_cases = []
        
        for section in sections:
            # Extract modulus size
            mod_match = re.search(r'# "SigGen PKCS#1 Ver1.5".*?Mod Size (\d+)', content)
            if mod_match:
                mod_size = int(mod_match.group(1))
            else:
                # Try to infer from the section
                lines = section.strip().split('\n')
                mod_size = 2048  # default
            
            # Extract n, e, d from the section
            n_match = re.search(r'^n = ([0-9a-fA-F]+)', section, re.MULTILINE)
            e_match = re.search(r'^e = ([0-9a-fA-F]+)', section, re.MULTILINE)
            d_match = re.search(r'^d = ([0-9a-fA-F]+)', section, re.MULTILINE)
            
            if not all([n_match, e_match, d_match]):
                continue
            
            n = int(n_match.group(1), 16)
            e = int(e_match.group(1), 16)
            d = int(d_match.group(1), 16)
            
            # Extract all test vectors in this section
            # Pattern to match SHAAlg = XXX followed by Msg = XXX and S = XXX
            pattern = r'SHAAlg = (SHA\d+)\s*\nMsg = ([0-9a-fA-F]+)\s*\nS = ([0-9a-fA-F]+)'
            
            for match in re.finditer(pattern, section):
                sha_alg = match.group(1)
                msg = match.group(2)
                signature = match.group(3)
                
                test_case = {
                    'modulus_size': mod_size,
                    'n': n,
                    'e': e,
                    'd': d,
                    'sha_alg': sha_alg,
                    'message': msg,
                    'expected_signature': int(signature, 16)
                }
                
                test_cases.append(test_case)
        
        return test_cases
    
    def create_rsa_from_params(self, n: int, e: int, d: int) -> RSA:
        """Create an RSA instance with specific parameters."""
        # Create a new RSA instance but override its generated values
        rsa = RSA.__new__(RSA)  # Create without calling __init__
        
        # We need to factor n to get p and q
        # For testing purposes, we'll use a simple factorization method
        # This works for the test vectors since they use specific constructions
        p, q = self._factor_n(n, e, d)
        
        # Set the parameters
        rsa.p = p
        rsa.q = q
        rsa.n = n
        rsa.phi = (p - 1) * (q - 1)
        rsa.public_key = (e, n)
        rsa.private_key = (d, n)
        rsa.bit_size = n.bit_length()
        
        return rsa
    
    def _factor_n(self, n: int, e: int, d: int) -> Tuple[int, int]:
        """Factor n using the relationship between e and d."""
        import random
        
        # Use the fact that ed - 1 = k * φ(n) for some integer k
        k = e * d - 1
        
        # Factor out powers of 2
        t = 0
        r = k
        while r % 2 == 0:
            t += 1
            r //= 2
        
        # Try to find factors
        for _ in range(100):
            a = random.randrange(2, n)
            y = pow(a, r, n)
            
            if y == 1 or y == n - 1:
                continue
            
            for _ in range(t - 1):
                x = pow(y, 2, n)
                if x == 1:
                    p = self._gcd(y - 1, n)
                    if 1 < p < n:
                        q = n // p
                        return (p, q) if p < q else (q, p)
                if x == n - 1:
                    break
                y = x
        
        raise ValueError(f"Could not factor n")
    
    def _gcd(self, a: int, b: int) -> int:
        """Calculate GCD of a and b."""
        while b:
            a, b = b, a % b
        return a


class NISTSignatureTest:
    """Test runner for NIST RSA signature test vectors."""
    
    def __init__(self):
        self.parser = NISTTestParser()
        self.test_cases = self.parser.parse_file()
        
    def run_test(self, test_case: Dict) -> Dict:
        """Run a single test case."""
        result = {
            'sha_alg': test_case['sha_alg'],
            'passed': False,
            'error': None
        }
        
        try:
            # Create RSA instance with the specific parameters
            rsa = self.parser.create_rsa_from_params(
                test_case['n'],
                test_case['e'],
                test_case['d']
            )
            
            # Convert hex message to bytes
            message_bytes = bytes.fromhex(test_case['message'])
            
            # Sign the message
            signature = rsa.sign(message_bytes, hash_alg=test_case['sha_alg'])
            
            # Compare with expected signature
            expected_sig = test_case['expected_signature']
            
            result['generated_signature'] = signature
            result['expected_signature'] = expected_sig
            result['passed'] = (signature == expected_sig)
            
            # Also verify the signature
            is_valid = rsa.verify(expected_sig, rsa.public_key, message_bytes, test_case['sha_alg'])
            result['verification'] = is_valid
            
            if not result['passed']:
                result['error'] = f"Signature mismatch. Generated: {hex(signature)[:50]}..., Expected: {hex(expected_sig)[:50]}..."
            elif not is_valid:
                result['error'] = "Signature verification failed"
                
        except Exception as e:
            import traceback
            result['error'] = f"{str(e)}\n{traceback.format_exc()}"
            
        return result
    
    def run_all_tests(self, limit: Optional[int] = None) -> List[Dict]:
        """Run all test cases."""
        if not self.test_cases:
            print("No test cases found.")
            return []
        
        results = []
        total_tests = len(self.test_cases)
        tests_to_run = min(limit, total_tests) if limit else total_tests
        
        print(f"Found {total_tests} test cases in NIST test vectors")
        print(f"Running {tests_to_run} tests...\n")
        
        # Group tests by SHA algorithm for better reporting
        sha_groups = {}
        for test_case in self.test_cases[:tests_to_run]:
            sha_alg = test_case['sha_alg']
            if sha_alg not in sha_groups:
                sha_groups[sha_alg] = []
            sha_groups[sha_alg].append(test_case)
        
        for sha_alg, cases in sha_groups.items():
            print(f"\nTesting {sha_alg} ({len(cases)} cases):")
            
            for i, test_case in enumerate(cases, 1):
                result = self.run_test(test_case)
                results.append(result)
                
                if result['passed']:
                    print(f"  Test {i}: ✓ PASSED")
                else:
                    print(f"  Test {i}: ✗ FAILED - {result['error']}")
        
        return results
    
    def print_summary(self, results: List[Dict]):
        """Print test summary."""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success rate: {(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "N/A")
        
        # Group by SHA algorithm
        sha_results = {}
        for result in results:
            sha_alg = result['sha_alg']
            if sha_alg not in sha_results:
                sha_results[sha_alg] = {'passed': 0, 'failed': 0}
            
            if result['passed']:
                sha_results[sha_alg]['passed'] += 1
            else:
                sha_results[sha_alg]['failed'] += 1
        
        print("\nResults by SHA algorithm:")
        for sha_alg, counts in sorted(sha_results.items()):
            total = counts['passed'] + counts['failed']
            print(f"  {sha_alg}: {counts['passed']}/{total} passed")


def main():
    """Main function to run the NIST test vectors."""
    print("NIST RSA PKCS#1 v1.5 Signature Test Suite")
    print("=" * 60)
    
    # Initialize test suite
    test_suite = NISTSignatureTest()
    
    # Run tests (limit to first 20 for demonstration, remove limit to run all)
    results = test_suite.run_all_tests(limit=20)
    
    # Print summary
    if results:
        test_suite.print_summary(results)
    
    # Exit with appropriate code
    failed_count = sum(1 for r in results if not r['passed'])
    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()