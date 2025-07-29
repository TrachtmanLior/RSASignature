#!/usr/bin/env python3
"""
Test file for RSA signature verification.
Reads test cases from a JSON file and compares generated signatures 
with hardcoded expected signatures.
"""

import json
import sys
import os
from typing import Dict, List, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rsasignature.rsa import RSA


class RSASignatureTest:
    """Test class for RSA signature verification."""
    
    def __init__(self, test_data_file: str = "test_data.json"):
        """
        Initialize the test with data from JSON file.
        
        Args:
            test_data_file: Path to JSON file containing test cases
        """
        self.test_data_file = test_data_file
        self.test_cases = self._load_test_data()
        
    def _load_test_data(self) -> List[Dict[str, Any]]:
        """Load test data from JSON file."""
        try:
            with open(self.test_data_file, 'r') as f:
                data = json.load(f)
                
                # Debug: Print the loaded data structure
                print(f"Loaded JSON data type: {type(data)}")
                print(f"JSON data keys: {data.keys() if isinstance(data, dict) else 'Not a dict'}")
                
                test_cases = data.get('test_cases', [])
                print(f"Test cases type: {type(test_cases)}")
                print(f"Number of test cases: {len(test_cases) if isinstance(test_cases, list) else 'Not a list'}")
                
                # Validate test cases structure
                if not isinstance(test_cases, list):
                    print("Error: 'test_cases' should be a list")
                    return []
                
                for i, case in enumerate(test_cases):
                    if not isinstance(case, dict):
                        print(f"Error: Test case {i} is not a dictionary: {type(case)}")
                    else:
                        required_keys = ['name', 'message', 'rsa_params', 'expected_signature']
                        missing_keys = [key for key in required_keys if key not in case]
                        if missing_keys:
                            print(f"Warning: Test case {i} missing keys: {missing_keys}")
                
                return test_cases
                
        except FileNotFoundError:
            print(f"Error: Test data file '{self.test_data_file}' not found.")
            print("Creating sample test data file...")
            self._create_sample_test_data()
            return []
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{self.test_data_file}': {e}")
            print("Please check your JSON syntax.")
            return []
        except Exception as e:
            print(f"Unexpected error loading test data: {e}")
            return []
    
    def _create_sample_test_data(self):
        """Create a sample test data file with example test cases."""
        # Generate some test signatures for demonstration
        rsa = RSA(size=512)  # Small key size for testing
        
        sample_data = {
            "test_cases": [
                {
                    "name": "Test Case 1",
                    "message": "hello",
                    "rsa_params": {
                        "n": rsa.n,
                        "e": rsa.public_key[0],
                        "d": rsa.private_key[0]
                    },
                    "expected_signature": rsa.sign("hello")
                },
                {
                    "name": "Test Case 2", 
                    "message": "test message",
                    "rsa_params": {
                        "n": rsa.n,
                        "e": rsa.public_key[0],
                        "d": rsa.private_key[0]
                    },
                    "expected_signature": rsa.sign("test message")
                }
            ]
        }
        
        with open(self.test_data_file, 'w') as f:
            json.dump(sample_data, f, indent=2)
        print(f"Sample test data created in '{self.test_data_file}'")
    
    def _factor_n(self, n: int, e: int, d: int) -> tuple:
        """
        Factor n into p and q using the RSA parameters n, e, and d.
        
        This uses the fact that ed ≡ 1 (mod φ(n)) and some number theory
        to recover the prime factors.
        
        Args:
            n: RSA modulus
            e: Public exponent
            d: Private exponent
            
        Returns:
            Tuple (p, q) where p and q are the prime factors of n
        """
        import random
        
        # Calculate k = ed - 1
        k = e * d - 1
        
        # Factor out powers of 2 from k: k = 2^t * r where r is odd
        t = 0
        r = k
        while r % 2 == 0:
            t += 1
            r //= 2
        
        # Try to find a factor using the probabilistic algorithm
        for _ in range(100):  # Try up to 100 times
            # Choose random a where 1 < a < n
            a = random.randrange(2, n)
            
            # Compute y = a^r mod n
            y = pow(a, r, n)
            
            if y == 1 or y == n - 1:
                continue
                
            # Square y up to t-1 times
            for _ in range(t - 1):
                x = pow(y, 2, n)
                if x == 1:
                    # Found a non-trivial square root of 1
                    p = self._gcd(y - 1, n)
                    if 1 < p < n:
                        q = n // p
                        return (p, q) if p < q else (q, p)
                if x == n - 1:
                    break
                y = x
        
        # If probabilistic method fails, try simple trial division for small factors
        # This is a fallback for small test cases
        for i in range(3, min(int(n**0.5) + 1, 1000000), 2):
            if n % i == 0:
                p, q = i, n // i
                return (p, q) if p < q else (q, p)
        
        raise ValueError(f"Could not factor n = {n}")
    
    def _gcd(self, a: int, b: int) -> int:
        """Calculate the greatest common divisor of a and b."""
        while b:
            a, b = b, a % b
        return a
    
    def _recreate_rsa_from_params(self, params: Dict[str, int]) -> RSA:
        """
        Recreate an RSA instance from stored parameters.
        
        Args:
            params: Dictionary containing RSA parameters. Can contain:
                   - n, e, d (will generate p, q)
                   - OR n, e, d, p, q (will use provided p, q)
                   Values can be integers or hex strings
            
        Returns:
            RSA instance with the specified parameters
        """
        # Create a new RSA instance but override its generated values
        rsa = RSA.__new__(RSA)  # Create without calling __init__
        
        # Convert hex strings to integers if needed
        def parse_param(value):
            if isinstance(value, str):
                # Remove any whitespace and convert from hex
                return int(value.replace(' ', ''), 16)
            return value
        
        n = parse_param(params['n'])
        e = parse_param(params['e'])
        d = parse_param(params['d'])
        
        print(f"Parsed parameters:")
        print(f"  n = {n}")
        print(f"  e = {e}")
        print(f"  d = {d}")
        
        # Check if p and q are provided, otherwise generate them
        if 'p' in params and 'q' in params:
            p = parse_param(params['p'])
            q = parse_param(params['q'])
            # Verify that p * q == n
            if p * q != n:
                raise ValueError(f"Provided p and q don't multiply to n: {p} * {q} = {p*q}, but n = {n}")
        else:
            # Generate p and q by factoring n
            print(f"Factoring n = {n} to find p and q...")
            p, q = self._factor_n(n, e, d)
            print(f"Found factors: p = {p}, q = {q}")
        
        # Set the parameters
        rsa.p = p
        rsa.q = q
        rsa.n = n
        rsa.phi = (p - 1) * (q - 1)
        rsa.public_key = (e, n)
        rsa.private_key = (d, n)
        rsa.bit_size = n.bit_length()
        
        # Verify that the parameters are consistent
        if (e * d) % rsa.phi != 1:
            raise ValueError(f"Invalid RSA parameters: ed ≢ 1 (mod φ(n))")
        
        return rsa
    
    def test_signature_verification(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a single signature verification case.
        
        Args:
            test_case: Dictionary containing test case data
            
        Returns:
            Dictionary with test results
        """
        result = {
            'name': test_case['name'],
            'message': test_case['message'],
            'passed': False,
            'error': None,
            'details': {}
        }
        
        try:
            # Recreate RSA instance from stored parameters
            rsa = self._recreate_rsa_from_params(test_case['rsa_params'])
            
            # Parse the message - it could be hex-encoded or plain text
            message = test_case['message']
            
            # Check if message appears to be hex (all hex characters and even length)
            if self._is_hex_string(message):
                print(f"Treating message as hex-encoded: {message[:60]}...")
                # Convert hex string to bytes, then to integer for signing
                message_bytes = bytes.fromhex(message)
                message_int = int.from_bytes(message_bytes, 'big')
                generated_signature = rsa.sign(message_int)
                
                # For verification, we'll compare the recovered message as bytes
                verified_message_int = rsa.verify(generated_signature, rsa.public_key)
                verified_message_bytes = rsa.recover_string(verified_message_int)
                verification_correct = verified_message_bytes == message_bytes
                verified_message_display = verified_message_bytes.hex()
            else:
                print(f"Treating message as plain text: {message}")
                # Handle as regular text string
                generated_signature = rsa.sign(message)
                verified_message_int = rsa.verify(generated_signature, rsa.public_key)
                verified_message_bytes = rsa.recover_string(verified_message_int)
                verified_message_display = verified_message_bytes.decode('utf-8')
                verification_correct = verified_message_display == message
            
            # Parse expected signature (could be hex string or integer)
            expected_signature_raw = test_case['expected_signature']
            if isinstance(expected_signature_raw, str):
                expected_signature = int(expected_signature_raw.replace(' ', ''), 16)
            else:
                expected_signature = expected_signature_raw
            
            print(f"Generated signature: {generated_signature}")
            print(f"Expected signature:  {expected_signature}")
            
            # Compare signatures
            signatures_match = generated_signature == expected_signature
            
            # Also verify the expected signature
            try:
                expected_verified_int = rsa.verify(expected_signature, rsa.public_key)
                expected_verified_bytes = rsa.recover_string(expected_verified_int)
                
                if self._is_hex_string(message):
                    expected_verification_correct = expected_verified_bytes == message_bytes
                else:
                    expected_verification_correct = expected_verified_bytes.decode('utf-8') == message
            except:
                expected_verification_correct = False
            
            result['passed'] = signatures_match and verification_correct and expected_verification_correct
            result['details'] = {
                'generated_signature': generated_signature,
                'expected_signature': expected_signature,
                'signatures_match': signatures_match,
                'verified_message': verified_message_display,
                'verification_correct': verification_correct,
                'expected_verification_correct': expected_verification_correct,
                'rsa_n': rsa.n,
                'rsa_e': rsa.public_key[0],
                'message_type': 'hex' if self._is_hex_string(message) else 'text'
            }
            
        except Exception as e:
            import traceback
            result['error'] = f"{str(e)}\n{traceback.format_exc()}"
            
        return result
    
    def _is_hex_string(self, s: str) -> bool:
        """
        Check if a string appears to be a hexadecimal string.
        
        Args:
            s: String to check
            
        Returns:
            True if string appears to be hex, False otherwise
        """
        if not s:
            return False
        
        # Remove any whitespace
        s_clean = s.replace(' ', '').replace('\n', '').replace('\t', '')
        
        # Check if all characters are hex digits and length is even
        try:
            int(s_clean, 16)
            return len(s_clean) % 2 == 0 and len(s_clean) > 0
        except ValueError:
            return False
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """
        Run all test cases and return results.
        
        Returns:
            List of test results
        """
        if not self.test_cases:
            print("No test cases to run.")
            return []
        
        results = []
        print(f"Running {len(self.test_cases)} test cases...\n")
        
        for i, test_case in enumerate(self.test_cases, 1):
            # Debug: Check what type test_case is
            if not isinstance(test_case, dict):
                print(f"Error: test_case is not a dictionary, it's a {type(test_case)}: {test_case}")
                continue
                
            # Safely get the test name
            test_name = test_case.get('name', f'Test {i}')
            print(f"Running test {i}: {test_name}")
            
            result = self.test_signature_verification(test_case)
            results.append(result)
            
            if result['passed']:
                print("✓ PASSED")
            else:
                print("✗ FAILED")
                if result['error']:
                    print(f"  Error: {result['error']}")
                else:
                    details = result.get('details', {})
                    if not details.get('signatures_match', True):
                        print(f"  Signatures don't match:")
                        print(f"    Generated: {details.get('generated_signature', 'N/A')}")
                        print(f"    Expected:  {details.get('expected_signature', 'N/A')}")
                    if not details.get('verification_correct', True):
                        print(f"  Verification failed for generated signature")
                    if not details.get('expected_verification_correct', True):
                        print(f"  Verification failed for expected signature")
            print()
        
        return results
    
    def print_summary(self, results: List[Dict[str, Any]]):
        """Print a summary of test results."""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['passed'])
        failed_tests = total_tests - passed_tests
        
        print("=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success rate: {(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "N/A")
        
        if failed_tests > 0:
            print("\nFailed tests:")
            for result in results:
                if not result['passed']:
                    error_msg = f" - {result['error']}" if result['error'] else ""
                    print(f"  • {result['name']}{error_msg}")


def main():
    """Main function to run the tests."""
    print("RSA Signature Test Suite")
    print("=" * 30)
    
    # Initialize test suite
    test_suite = RSASignatureTest()
    
    # Run all tests
    results = test_suite.run_all_tests()
    
    # Print summary
    if results:
        test_suite.print_summary(results)
    
    # Exit with appropriate code
    failed_count = sum(1 for r in results if not r['passed'])
    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()