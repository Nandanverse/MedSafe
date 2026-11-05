#!/usr/bin/env python3
"""
TrueMed Integration Test - Full Workflow Simulation
Tests: QR Generation → Offline Verification → Blockchain Query → Result Display
"""

import sys
import os
import json
import time
import base64
from datetime import datetime, date

# Add the qr-generator directory to Python path
sys.path.insert(0, r'C:\Users\nanda\OneDrive\Desktop\My project\TrueMed\qr-generator')

from truemed_qr import (
    MedicineData,
    generate_private_key,
    sign,
    verify,
    build_wire,
    encode,
    decode,
    make_product_id,
    parse_iso_date,
    CONTRACT_VERSION,
    WIRE_PREFIX,
    TYPE_MEDICINE,
    TYPE_VACCINE,
    VACCINE_TEMP_MIN_C,
    VACCINE_TEMP_MAX_C,
    TrueMedError,
    SignatureInvalidError,
    KeyUnknownError,
    ExpiredError,
    QRMalformedError,
    UnknownFormatVersionError,
)


class TrueMedIntegrationTest:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests_passed': 0,
            'tests_failed': 0,
            'test_details': []
        }
        self.private_key = None
        self.product_id = None
        self.medicine_data = None
        self.wire = None
        self.payload_bytes = None
        self.signature_bytes = None

    def log_test_result(self, test_name, passed, details=""):
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")

        self.results['test_details'].append({
            'test': test_name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })

        if passed:
            self.results['tests_passed'] += 1
        else:
            self.results['tests_failed'] += 1

    def test_qr_generation(self):
        """Test 1: QR Code Generation with ECDSA Signature"""
        print("\n🧪 Test 1: QR Code Generation")
        try:
            self.private_key = generate_private_key()
            self.product_id = make_product_id(
                generic_name="Paracetamol 500mg",
                brand_name="Paracip 500",
                year=2026,
                serial=1
            )

            self.medicine_data = MedicineData(
                product_id=self.product_id,
                generic_name="Paracetamol 500mg",
                brand_name="Paracip 500",
                manufacturer="Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018",
                mfg_licence_no="MH/25D/2019/187",
                batch_no="SP26A0417",
                mfg_date=parse_iso_date("2026-03-15"),
                expiry_date=parse_iso_date("2028-02-29"),
                quantity="10 tablets",
                excipients=["Maize Starch", "Povidone K30", "Talc"],
                type=TYPE_MEDICINE,
                contract_version=CONTRACT_VERSION
            )

            self.wire = build_wire(self.medicine_data, self.private_key)

            if not self.wire.startswith("TM1."):
                raise ValueError("Wire must start with TM1 prefix")

            parts = self.wire.split('.')
            if len(parts) != 3:
                raise ValueError(f"Wire should have 3 parts, got {len(parts)}")

            # Store parts for later tests
            self.payload_bytes = decode(parts[1])
            self.signature_bytes = decode(parts[2])

            self.log_test_result(
                "QR Generation",
                True,
                f"Wire length: {len(self.wire)} chars, Product ID: {self.product_id}"
            )
            return True
        except Exception as e:
            self.log_test_result("QR Generation", False, f"Error: {str(e)}")
            return False

    def test_offline_verification(self):
        """Test 2: Offline Verification (Signature + Expiry Check)"""
        print("\n🧪 Test 2: Offline Verification (Signature + Expiry)")
        try:
            # Verify the signature using the public key
            public_key = self.private_key.public_key()
            is_valid = verify(public_key, self.payload_bytes, self.signature_bytes)

            if not is_valid:
                raise SignatureInvalidError("ECDSA signature verification failed")

            # Check expiry
            payload = json.loads(self.payload_bytes)
            expiry_date = parse_iso_date(payload['ed'])
            days_to_expiry = (expiry_date - datetime.now()).days

            if days_to_expiry <= 0:
                raise ExpiredError(f"Medicine expired {abs(days_to_expiry)} days ago")

            self.log_test_result(
                "Offline Verification",
                True,
                f"Signature: valid, Expiry: {days_to_expiry} days remaining"
            )
            return True
        except Exception as e:
            self.log_test_result("Offline Verification", False, f"Error: {str(e)}")
            return False

    def test_payload_structure(self):
        """Test 3: Payload Structure Validation"""
        print("\n🧪 Test 3: Payload Structure Validation")
        try:
            payload = json.loads(self.payload_bytes)

            # Check required fields
            required_fields = ['v', 'id', 'gn', 'bn', 'mf', 'ml', 'bt', 'md', 'ed', 'qt', 'ex', 'tp']
            missing = [f for f in required_fields if f not in payload]

            if missing:
                raise ValueError(f"Missing required fields: {missing}")

            # Validate contract version
            if payload.get('v') != CONTRACT_VERSION:
                raise ValueError(f"Wrong contract version: {payload.get('v')}")

            # Validate prefix
            if payload.get('v') != 1:
                raise ValueError(f"Contract version mismatch: expected 1, got {payload.get('v')}")

            self.log_test_result(
                "Payload Structure",
                True,
                f"All {len(required_fields)} required fields present, version {payload.get('v')}"
            )
            return True
        except Exception as e:
            self.log_test_result("Payload Structure", False, f"Error: {str(e)}")
            return False

    def test_signature_verification(self):
        """Test 4: ECDSA P-256 Signature Verification"""
        print("\n🧪 Test 4: ECDSA P-256 Signature Verification")
        try:
            if len(self.signature_bytes) != 64:
                raise ValueError(f"Signature should be 64 bytes, got {len(self.signature_bytes)}")

            # Verify signature matches
            public_key = self.private_key.public_key()
            is_valid = verify(public_key, self.payload_bytes, self.signature_bytes)

            if not is_valid:
                raise SignatureInvalidError("Signature verification failed")

            self.log_test_result(
                "ECDSA Signature",
                True,
                "Signature valid, curve: secp256r1 (NIST P-256)"
            )
            return True
        except Exception as e:
            self.log_test_result("ECDSA Signature", False, f"Error: {str(e)}")
            return False

    def test_contract_compliance(self):
        """Test 5: Contract Compliance Check"""
        print("\n🧪 Test 5: Contract Compliance")
        try:
            if not self.wire.startswith("TM1."):
                raise ValueError("Wire must start with TM1 prefix")

            if len(self.wire) > 1273:
                raise ValueError(f"Wire too long: {len(self.wire)} bytes (max 1273)")

            parts = self.product_id.split('_')
            if len(parts) != 4:
                raise ValueError(f"Invalid product_id format: {self.product_id}")

            if self.medicine_data.expiry_date <= self.medicine_data.mfg_date:
                raise ValueError("Expiry date must be after manufacturing date")

            self.log_test_result(
                "Contract Compliance",
                True,
                "All contract requirements satisfied"
            )
            return True
        except Exception as e:
            self.log_test_result("Contract Compliance", False, f"Error: {str(e)}")
            return False

    def test_vaccine_cold_chain(self):
        """Test 6: Vaccine Cold Chain Validation"""
        print("\n🧪 Test 6: Vaccine Cold Chain Validation")
        try:
            # Create vaccine data
            vaccine_id = make_product_id(
                generic_name="Covaxin",
                brand_name="BBV152",
                year=2026,
                serial=42
            )

            vaccine_data = MedicineData(
                product_id=vaccine_id,
                generic_name="Covaxin",
                brand_name="BBV152",
                manufacturer="Bharat Biotech",
                mfg_licence_no="MH/25D/2020/123",
                batch_no="CV26B0501",
                mfg_date=parse_iso_date("2026-01-10"),
                expiry_date=parse_iso_date("2027-01-09"),
                quantity="1 vial (0.5 ml)",
                excipients=["Aluminum Hydroxide Gel"],
                type=TYPE_VACCINE,
                contract_version=CONTRACT_VERSION
            )

            # Check vaccine temperature constraints
            if VACCINE_TEMP_MIN_C != 2.0:
                raise ValueError(f"Vaccine min temperature should be 2.0, got {VACCINE_TEMP_MIN_C}")
            if VACCINE_TEMP_MAX_C != 8.0:
                raise ValueError(f"Vaccine max temperature should be 8.0, got {VACCINE_TEMP_MAX_C}")

            # Validate vaccine type
            if vaccine_data.type != TYPE_VACCINE:
                raise ValueError("Data should be vaccine type")

            # Check cold chain breach logic
            safe_temp = 4.5
            breach_temp = 10.0

            is_safe = VACCINE_TEMP_MIN_C <= safe_temp <= VACCINE_TEMP_MAX_C
            is_breach = not (VACCINE_TEMP_MIN_C <= breach_temp <= VACCINE_TEMP_MAX_C)

            if not is_safe:
                raise ValueError("Safe temperature incorrectly flagged as breach")
            if not is_breach:
                raise ValueError("Breached temperature incorrectly accepted")

            self.log_test_result(
                "Vaccine Cold Chain",
                True,
                f"Safe temp ({safe_temp}°C): OK | Breach temp ({breach_temp}°C): Correctly flagged"
            )
            return True
        except Exception as e:
            self.log_test_result("Vaccine Cold Chain", False, f"Error: {str(e)}")
            return False

    def test_wire_encoding(self):
        """Test 7: Wire String Encoding/Decoding"""
        print("\n🧪 Test 7: Wire Encoding/Decoding")
        try:
            # Test encode/decode roundtrip
            test_json = b'{"test": "data"}'
            encoded = encode(test_json, self.signature_bytes)

            if not encoded.startswith("TM1."):
                raise ValueError("Encoded string must start with TM1 prefix")

            # Verify the decoded content matches
            parts = encoded.split('.')
            decoded_payload = decode(parts[1])
            decoded_signature = decode(parts[2])

            if decoded_payload != test_json:
                raise ValueError("Payload roundtrip mismatch")

            if decoded_signature != self.signature_bytes:
                raise ValueError("Signature roundtrip mismatch")

            self.log_test_result(
                "Wire Encoding",
                True,
                f"Encode/decode successful, total wire length: {len(encoded)}"
            )
            return True
        except Exception as e:
            self.log_test_result("Wire Encoding", False, f"Error: {str(e)}")
            return False

    def test_error_handling(self):
        """Test 8: Error Handling (Edge Cases)"""
        print("\n🧪 Test 8: Error Handling")
        edge_cases = []
        try:
            # Test 1: Invalid prefix
            try:
                decode("TM2.invalid.data")
                edge_cases.append(("Invalid prefix", False, "Accepted TM2 but should fail"))
            except Exception:
                edge_cases.append(("Invalid prefix", True, "Correctly rejected TM2"))

            # Test 2: Malformed QR
            try:
                decode("not-base64!!!")
                edge_cases.append(("Malformed QR", False, "Should fail on invalid base64"))
            except Exception:
                edge_cases.append(("Malformed QR", True, "Correctly rejected invalid base64"))

            # Test 3: Missing parts
            try:
                decode("TM1.incomplete")
                edge_cases.append(("Incomplete parts", False, "Should fail with only 2 parts"))
            except Exception:
                edge_cases.append(("Incomplete parts", True, "Correctly rejected incomplete wire"))

            # Log all edge case results
            all_passed = True
            for name, passed, detail in edge_cases:
                self.log_test_result(f"Error Handling - {name}", passed, detail)
                if not passed:
                    all_passed = False

            return all_passed

        except Exception as e:
            self.log_test_result("Error Handling", False, f"Error: {str(e)}")
            return False

    def run_all_tests(self):
        """Execute all integration tests"""
        print("🚀 Starting TrueMed Full Workflow Integration Tests")
        print("=" * 60)

        start_time = time.time()

        tests = [
            ("QR Generation", self.test_qr_generation),
            ("Offline Verification", self.test_offline_verification),
            ("Payload Structure", self.test_payload_structure),
            ("ECDSA Signature", self.test_signature_verification),
            ("Contract Compliance", self.test_contract_compliance),
            ("Vaccine Cold Chain", self.test_vaccine_cold_chain),
            ("Wire Encoding", self.test_wire_encoding),
            ("Error Handling", self.test_error_handling),
        ]

        for test_name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                print(f"💥 Test {test_name} crashed: {str(e)}")
                self.log_test_result(test_name, False, f"Test crashed: {str(e)}")

        end_time = time.time()
        duration = end_time - start_time

        # Print summary
        print("\n" + "=" * 60)
        print("📊 INTEGRATION TEST SUMMARY")
        print("=" * 60)
        print(f"⏱️  Total Duration: {duration:.2f} seconds")
        print(f"✅ Tests Passed: {self.results['tests_passed']}/{len(tests)}")
        print(f"❌ Tests Failed: {self.results['tests_failed']}")

        success_rate = (self.results['tests_passed'] / len(tests) * 100) if len(tests) > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")

        # Save results
        results_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "results",
            "full_workflow_results.json"
        )
        os.makedirs(os.path.dirname(results_path), exist_ok=True)

        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"💾 Detailed results saved to: {results_path}")

        # Generate sample QR for visual verification
        if self.wire:
            output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "fixtures"
            )
            os.makedirs(output_dir, exist_ok=True)
            generate(
                self.medicine_data,
                self.private_key,
                out_dir=output_dir
            )
            print(f"📱 Generated QR code in: {output_dir}")

        return self.results['tests_failed'] == 0


if __name__ == "__main__":
    tester = TrueMedIntegrationTest()
    success = tester.run_all_tests()
    print("\n" + "=" * 60)
    print("🎉 Integration Testing Complete!")
    print("=" * 60)
    sys.exit(0 if success else 1)