# tests/test_blockchain.py

import os
import unittest
os.environ["SECRET_KEY"] = "your_secret_key_here"
from sasu.blockchain import Blockchain
 # Mengimpor kelas Blockchain dari file utama

class TestBlockchain(unittest.TestCase):

    def setUp(self):
        self.blockchain = Blockchain()  # Inisialisasi objek Blockchain baru untuk setiap uji

    def test_new_transaction_valid(self):
        # Menguji transaksi yang valid
        result = self.blockchain.new_transaction('test_sender', 'test_recipient', 10)
        self.assertTrue(result)
        self.assertEqual(len(self.blockchain.current_transactions), 1)

    def test_new_transaction_invalid_amount(self):
        # Menguji transaksi dengan jumlah yang tidak valid
        result = self.blockchain.new_transaction('test_sender', 'test_recipient', -5)
        self.assertFalse(result)
        self.assertEqual(len(self.blockchain.current_transactions), 0)

if __name__ == '__main__':
    unittest.main()