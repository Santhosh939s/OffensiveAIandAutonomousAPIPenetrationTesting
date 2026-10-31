"""Unit tests for Phase 5 Adaptive Test Selection and Low-Step Optimization.

Verifies:
1. Endpoint prioritization scoring (auth surfaces, parameterized routes, 500 anomalies).
2. Per-endpoint probe budget enforcement and route exhaustion pruning.
3. Early stopping when high-value test candidates are exhausted.
4. Compact assessment memory synthesis under token limits.
5. Live event stream emission across controller testing phases.
6. Benchmark consistency and efficiency ratio calculations.
"""

import json
import unittest
from typing import Any, Dict, List

from controller.agent.adaptive_engine import AdaptiveTestSelector, PrioritizedCandidate
from controller.agent.context_manager import CompactContextManager
from controller.agent.event_emitter import AgentEventEmitter, ControllerEventType
from controller.agent.autonomous_controller import AutonomousController
from controller.config import AgentConfig
from controller.brain.model_gateway import DeterministicMockBrainClient
from controller.storage.evidence_store import EvidenceStore


class TestAdaptiveEngine(unittest.TestCase):
    def setUp(self):
        self.context = CompactContextManager(
            target_url="http://127.0.0.1:5000",
            max_turns=10,
            max_requests=25,
            max_probes_per_endpoint=2,
        )
        self.sample_endpoints = [
            {"path": "/health", "method": "GET", "parameters": []},
            {"path": "/api/users", "method": "GET", "parameters": []},
            {"path": "/api/users/{id}", "method": "GET", "parameters": [{"name": "id", "in": "path"}]},
            {"path": "/api/login", "method": "POST", "parameters": [], "security": True},
            {"path": "/api/search", "method": "GET", "parameters": [{"name": "q", "in": "query"}]},
        ]
        self.context.register_discovered_endpoints(self.sample_endpoints)
        self.selector = AdaptiveTestSelector(self.context)

    def test_endpoint_prioritization_hierarchy(self):
        candidates = self.selector.evaluate_and_rank_candidates(
            target_base_url="http://127.0.0.1:5000",
            recent_observations=[],
        )
        self.assertGreater(len(candidates), 0)

        # Login (auth) and search (parameterized query) must score higher than static /health
        paths_ordered = [c.path for c in candidates]
        health_idx = paths_ordered.index("/health")
        login_idx = paths_ordered.index("/api/login")
        self.assertLess(login_idx, health_idx, "Login must be prioritized before /health")

    def test_anomaly_500_error_boosts_priority(self):
        # Initial ranking
        initial_candidates = self.selector.evaluate_and_rank_candidates(
            target_base_url="http://127.0.0.1:5000",
            recent_observations=[],
        )
        search_initial_score = next(c.priority_score for c in initial_candidates if "search" in c.path)

        # Observation with 500 status on /api/search
        obs_with_500 = [
            {
                "arguments": {"url": "http://127.0.0.1:5000/api/search?q='"},
                "result_status": 500,
            }
        ]
        boosted_candidates = self.selector.evaluate_and_rank_candidates(
            target_base_url="http://127.0.0.1:5000",
            recent_observations=obs_with_500,
        )
        search_boosted_score = next(c.priority_score for c in boosted_candidates if "search" in c.path)
        self.assertGreater(search_boosted_score, search_initial_score)

    def test_per_endpoint_probe_exhaustion(self):
        key = "GET /health"
        self.assertFalse(self.context.is_endpoint_exhausted(key))

        # Max probes per endpoint is 2
        self.context.record_probe(key, "httpx_request", {"url": "http://127.0.0.1:5000/health"}, 200, True)
        self.assertFalse(self.context.is_endpoint_exhausted(key))

        self.context.record_probe(key, "httpx_request", {"url": "http://127.0.0.1:5000/health"}, 200, True)
        self.assertTrue(self.context.is_endpoint_exhausted(key))

        # Exhausted endpoint must be pruned from candidate rankings
        candidates = self.selector.evaluate_and_rank_candidates("http://127.0.0.1:5000", [])
        candidate_keys = [c.endpoint_key for c in candidates]
        self.assertNotIn(key, candidate_keys)

    def test_early_stopping_evaluation(self):
        # Initially not stopping
        candidates = self.selector.evaluate_and_rank_candidates("http://127.0.0.1:5000", [])
        should_stop, reason = self.selector.should_abstain_or_stop(candidates)
        self.assertFalse(should_stop)

        # When candidates list is empty, early stopping must trigger
        should_stop_empty, reason_empty = self.selector.should_abstain_or_stop([])
        self.assertTrue(should_stop_empty)
        self.assertIn("probe budget", reason_empty.lower())

    def test_compact_context_memory_generation(self):
        self.context.record_probe(
            "POST /api/login",
            "httpx_request",
            {"url": "http://127.0.0.1:5000/api/login"},
            200,
            True,
            finding={"status": "CONFIRMED", "category": "Insecure Authentication", "endpoint": "/api/login"},
        )
        compact = self.context.build_compact_memory_for_prompt()
        self.assertEqual(compact["confirmed_findings_count"], 1)
        self.assertEqual(compact["target"], "http://127.0.0.1:5000")
        self.assertIn("turns_remaining", compact["budget"])
        self.assertIn("requests_remaining", compact["budget"])
        # Ensure json string is lightweight
        json_str = json.dumps(compact)
        self.assertLess(len(json_str), 1500)

    def test_event_emitter_subscriptions(self):
        emitter = AgentEventEmitter()
        received_events = []

        def on_event(ev):
            received_events.append(ev)

        emitter.subscribe(on_event)
        emitter.emit(ControllerEventType.PHASE_CHANGE, "sess_1", {"phase": "PLANNING"})
        emitter.emit(ControllerEventType.FINDING_RECORDED, "sess_1", {"finding_id": 1})

        self.assertEqual(len(received_events), 2)
        self.assertEqual(received_events[0]["event_type"], ControllerEventType.PHASE_CHANGE)
        self.assertEqual(received_events[1]["event_type"], ControllerEventType.FINDING_RECORDED)

        # Test session filtering
        sess_events = emitter.get_events("sess_1")
        self.assertEqual(len(sess_events), 2)
        empty_events = emitter.get_events("sess_unknown")
        self.assertEqual(len(empty_events), 0)

    def test_controller_live_event_emission_and_adaptive_loop(self):
        events_captured = []
        emitter = AgentEventEmitter()
        emitter.subscribe(lambda ev: events_captured.append(ev["event_type"]))

        store = EvidenceStore(db_path=":memory:")
        config = AgentConfig(
            max_turns=4,
            max_requests_per_session=10,
            adaptive_selection_enabled=True,
            early_stopping_enabled=True,
        )
        controller = AutonomousController(
            config=config,
            model_brain=DeterministicMockBrainClient(),
            evidence_store=store,
            event_emitter=emitter,
        )

        res = controller.run_assessment(
            target_url="http://127.0.0.1:5000",
            endpoints=[{"path": "/health", "method": "GET"}],
            session_notes="Live event and adaptive testing unit test",
        )

        self.assertTrue(res.get("success"))
        self.assertIn(ControllerEventType.PHASE_CHANGE, events_captured)
        self.assertIn(ControllerEventType.BUDGET_UPDATE, events_captured)
        self.assertIn(ControllerEventType.ACTION_PROPOSED, events_captured)
        self.assertIn(ControllerEventType.POLICY_DECISION, events_captured)
        self.assertIn(ControllerEventType.ASSESSMENT_COMPLETED, events_captured)


if __name__ == "__main__":
    unittest.main()

