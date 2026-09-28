import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([]!=json_search(key1,data,role="viewer"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([]==json_search(key2,data,role="viewer"))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1,data,role="viewer"),list)

    def test_wrong_role_cannot_read_secret(self):
        '''role không có quyền không được phép đọc apiKey'''
        result=json_search("apiKey",data,role="viewer")
        self.assertEqual([],result)

    def test_operator_cannot_read_apikey(self):
        '''operator không được phép đọc apiKey, chỉ admin mới được'''
        result=json_search("apiKey",data,role="operator")
        self.assertEqual([],result)

    def test_viewer_cannot_read_managementIpAddress(self):
        '''viewer không được phép đọc managementIpAddress'''
        result=json_search("managementIpAddress",data,role="viewer")
        self.assertEqual([],result)

if __name__ == '__main__':
    unittest.main()
