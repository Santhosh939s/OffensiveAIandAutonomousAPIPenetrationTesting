"""Unit Tests for GraphQL Security Probe Tool."""

import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from controller.tools.graphql_client import GraphQLProbeTool, SAFE_INTROSPECTION_QUERY
from controller.tools.registry import ToolRegistry


class TestGraphQLProbeTool(unittest.TestCase):
    """Test suite for GraphQLProbeTool discovery, schema inspection, and error handling."""

    def setUp(self):
        self.tool = GraphQLProbeTool()

    def test_schema_and_metadata(self):
        """Verify tool name, category, and parameters schema."""
        self.assertEqual(self.tool.name, "graphql_probe")
        self.assertEqual(self.tool.category, "reconnaissance")
        self.assertFalse(self.tool.is_destructive)
        desc = self.tool.get_description()
        self.assertIn("target_url", desc["parameters"]["properties"])

    def test_argument_validation(self):
        """Verify required parameters."""
        valid, err = self.tool.validate_arguments({})
        self.assertFalse(valid)
        self.assertIn("target_url", err)

        valid, err = self.tool.validate_arguments({"target_url": "http://127.0.0.1:5000/graphql"})
        self.assertTrue(valid)

    @patch("urllib.request.urlopen")
    def test_graphql_endpoint_detection_success(self, mock_urlopen):
        """Verify detection of an active GraphQL endpoint with introspection enabled."""
        # 1. Response for baseline __typename probe
        mock_resp1 = MagicMock()
        mock_resp1.status = 200
        mock_resp1.read.return_value = json.dumps({"data": {"__typename": "Query"}}).encode("utf-8")
        mock_resp1.__enter__.return_value = mock_resp1

        # 2. Response for safe introspection query
        mock_resp2 = MagicMock()
        mock_resp2.status = 200
        mock_resp2.read.return_value = json.dumps({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"name": "User", "kind": "OBJECT", "description": "Application user"},
                        {"name": "Query", "kind": "OBJECT", "description": "Root query"},
                        {"name": "__Schema", "kind": "OBJECT", "description": "Meta schema"},
                    ],
                }
            }
        }).encode("utf-8")
        mock_resp2.__enter__.return_value = mock_resp2

        mock_urlopen.side_effect = [mock_resp1, mock_resp2]

        result = self.tool.execute(target_url="http://127.0.0.1:5000/graphql")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["discovered_endpoints"]), 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["type"], "GRAPHQL_INTROSPECTION_ENABLED")
        self.assertEqual(finding["owasp_category"], "API8:2023 Security Misconfiguration")

    @patch("urllib.request.urlopen")
    def test_graphql_introspection_disabled(self, mock_urlopen):
        """Verify handling when introspection is disabled on the GraphQL endpoint."""
        # 1. Response for baseline probe (endpoint is GraphQL)
        mock_resp1 = MagicMock()
        mock_resp1.status = 200
        mock_resp1.read.return_value = json.dumps({"data": {"__typename": "Query"}}).encode("utf-8")
        mock_resp1.__enter__.return_value = mock_resp1

        # 2. Response for introspection query (disabled)
        mock_resp2 = MagicMock()
        mock_resp2.status = 200
        mock_resp2.read.return_value = json.dumps({
            "errors": [{"message": "GraphQL introspection is disabled."}]
        }).encode("utf-8")
        mock_resp2.__enter__.return_value = mock_resp2

        mock_urlopen.side_effect = [mock_resp1, mock_resp2]

        result = self.tool.execute(target_url="http://127.0.0.1:5000/graphql")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["discovered_endpoints"]), 1)
        self.assertEqual(len(result["findings"]), 0)
        intro = result["introspection_results"][0]
        self.assertFalse(intro["enabled"])

    @patch("urllib.request.urlopen")
    def test_non_graphql_endpoint(self, mock_urlopen):
        """Verify non-GraphQL endpoints return clean results with zero false discoveries."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><head><title>Not Found</title></head></html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = self.tool.execute(target_url="http://127.0.0.1:5000/api")
        self.assertEqual(len(result["discovered_endpoints"]), 0)
        self.assertEqual(len(result["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
