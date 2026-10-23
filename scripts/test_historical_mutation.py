import subprocess
import unittest
import historical_mutation as mutation

class EvidenceTests(unittest.TestCase):
    def test_environment_panic_is_not_mutation_detection(self):
        result = subprocess.CompletedProcess([], 1, '--- FAIL: TestSecurity (0.00s)\npanic: socket: operation not permitted', '')
        self.assertFalse(mutation.go_mutation_detected(result, 'TestSecurity'))

    def test_assertion_failure_detects_mutation(self):
        result = subprocess.CompletedProcess([], 1, '--- FAIL: TestSecurity (0.00s)\n    expected rejection', '')
        self.assertTrue(mutation.go_mutation_detected(result, 'TestSecurity'))

if __name__ == '__main__':
    unittest.main()
