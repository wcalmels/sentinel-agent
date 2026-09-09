"""Tests formales — Sentinel-Agent Completo — seed=42"""
import os, sys, json, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..','core'))

from phi47_base import PhiField, Welford, PHI, PHI_MIN
from efficient_orchestrator import (
    EfficientOrchestrator, PhiGate, RuleEngine,
    DecisionCache, FrontierLLM, Decision
)
from sentinel_agent_complete import (
    SentinelAgentComplete, NetworkProfiler,
    ThreatAnalyzer, SentinelMemory
)


class TestPhi47Base(unittest.TestCase):
    def test_phi_field_range(self):
        f = PhiField()
        self.assertGreater(f.phi_global, 0)
        self.assertLessEqual(f.phi_global, PHI)

    def test_degrade(self):
        f = PhiField(); f.nodes = [0.8]*12
        p1 = f.phi_global; f.degrade(0.3, [0,1,2])
        self.assertLessEqual(f.phi_global, p1)

    def test_boost(self):
        f = PhiField()
        f.nodes = [0.3,0.5,0.4,0.6]*3
        p1 = f.phi_global; f.boost(0.15)
        self.assertGreaterEqual(f.phi_global, p1)

    def test_welford_mean(self):
        w = Welford()
        for v in [1.0,2.0,3.0,4.0,5.0]: w.update(v)
        self.assertAlmostEqual(w.mean, 3.0, places=5)

    def test_welford_std(self):
        w = Welford()
        for v in [2.0,4.0,4.0,4.0,5.0,5.0,7.0,9.0]: w.update(v)
        self.assertGreater(w.std, 0)

    def test_phi_snapshot_keys(self):
        s = PhiField().snapshot()
        for k in ["phi_global","health","coherent","nodes"]:
            self.assertIn(k, s)


class TestPhiGate(unittest.TestCase):
    def setUp(self):
        self._phi  = PhiField()
        self._gate = PhiGate(self._phi)

    def test_healthy_phi_low_severity(self):
        # Phi alto + LOW → MONITOR directo
        self._phi.nodes = [0.9]*12
        d = self._gate.evaluate("LOW")
        self.assertIsNotNone(d)
        self.assertEqual(d.level, 0)

    def test_critical_not_filtered(self):
        # CRITICAL nunca se filtra
        self._phi.nodes = [0.9]*12
        d = self._gate.evaluate("CRITICAL")
        self.assertIsNone(d)

    def test_info_filtered(self):
        # INFO con phi coherente → IGNORE
        self._phi.nodes = [0.7]*12
        d = self._gate.evaluate("INFO")
        self.assertIsNotNone(d)
        self.assertEqual(d.action, "IGNORE")


class TestRuleEngine(unittest.TestCase):
    def setUp(self): self._rules = RuleEngine()

    def _ev(self, **kw) -> dict:
        return {"ip":"", "port":0, "pattern":"",
                "severity":"LOW", "anomaly_score":0.0, **kw}

    def test_ioc_ip_blocked(self):
        d = self._rules.evaluate(self._ev(ip="5.199.174.88"))
        self.assertIsNotNone(d)
        self.assertEqual(d.action, "BLOCK")
        self.assertGreater(d.confidence, 0.95)

    def test_malicious_port_blocked(self):
        d = self._rules.evaluate(self._ev(port=4444))
        self.assertIsNotNone(d)
        self.assertEqual(d.action, "BLOCK")

    def test_c2_beacon_blocked(self):
        d = self._rules.evaluate(self._ev(pattern="c2_beacon"))
        self.assertEqual(d.action, "BLOCK")

    def test_data_exfil_blocked(self):
        d = self._rules.evaluate(self._ev(pattern="data_exfil"))
        self.assertEqual(d.action, "BLOCK")

    def test_port_scan_alerted(self):
        d = self._rules.evaluate(self._ev(pattern="port_scan"))
        self.assertEqual(d.action, "ALERT")

    def test_low_score_monitored(self):
        d = self._rules.evaluate(self._ev(severity="LOW",anomaly_score=0.1))
        self.assertIsNotNone(d)
        self.assertEqual(d.action, "MONITOR")

    def test_ambiguous_returns_none(self):
        d = self._rules.evaluate(self._ev(
            ip="200.200.200.1", port=8888,
            severity="MEDIUM", anomaly_score=0.55))
        self.assertIsNone(d)


class TestDecisionCache(unittest.TestCase):
    def setUp(self): self._cache = DecisionCache()

    def _ev(self, **kw):
        return {"threat_type":"ANOMALY","severity":"MEDIUM",
                "pattern":"","port":443, **kw}

    def test_miss_on_empty(self):
        self.assertIsNone(self._cache.get(self._ev()))

    def test_hit_after_set(self):
        ev = self._ev()
        d  = Decision("BLOCK","test",0.9,2)
        self._cache.set(ev, d)
        cached = self._cache.get(ev)
        self.assertIsNotNone(cached)
        self.assertTrue(cached.cached)
        self.assertEqual(cached.action, "BLOCK")

    def test_same_category_hits(self):
        # IPs diferentes pero mismo perfil → mismo cache key
        ev1 = self._ev(port=443)
        ev2 = self._ev(port=443)
        d   = Decision("ALERT","test",0.8,2)
        self._cache.set(ev1, d)
        self.assertIsNotNone(self._cache.get(ev2))

    def test_different_type_miss(self):
        ev1 = self._ev(threat_type="IOC")
        ev2 = self._ev(threat_type="BEHAVIORAL")
        d   = Decision("BLOCK","test",0.9,2)
        self._cache.set(ev1, d)
        self.assertIsNone(self._cache.get(ev2))

    def test_stats_keys(self):
        s = self._cache.stats()
        for k in ["size","hits","misses","hit_rate"]:
            self.assertIn(k, s)


class TestEfficientOrchestrator(unittest.TestCase):
    def setUp(self):
        self._phi  = PhiField()
        self._orch = EfficientOrchestrator(self._phi, "demo")

    def _ev(self, **kw):
        return {"ip":"","port":0,"pattern":"",
                "severity":"LOW","anomaly_score":0.0,
                "threat_type":"ANOMALY","event_id":"t1", **kw}

    def test_ioc_resolved_by_rules(self):
        d = self._orch.decide(self._ev(ip="5.199.174.88",severity="CRITICAL",
                                       anomaly_score=1.0))
        self.assertEqual(d.action, "BLOCK")
        self.assertEqual(d.level, 1)
        self.assertEqual(d.tokens_used, 0)

    def test_low_phi_high_resolved(self):
        self._phi.nodes = [0.95]*12  # phi muy alto
        d = self._orch.decide(self._ev(severity="LOW"))
        self.assertEqual(d.level, 0)
        self.assertEqual(d.tokens_used, 0)

    def test_cache_used_second_time(self):
        ev = self._ev(severity="MEDIUM", port=8888, anomaly_score=0.55,
                      ip="200.200.200.1")
        self._orch.decide(ev)
        ev2 = dict(ev); ev2["ip"] = "200.200.200.2"
        d2  = self._orch.decide(ev2)
        self.assertTrue(d2.cached)

    def test_efficiency_keys(self):
        eff = self._orch.efficiency()
        for k in ["total","level_0","level_1","level_2_llm",
                  "llm_pct","target_met","tokens_total"]:
            self.assertIn(k, eff)

    def test_zero_tokens_for_rules(self):
        self._orch.decide(self._ev(ip="185.220.101.5",
                                   severity="CRITICAL", anomaly_score=1.0))
        eff = self._orch.efficiency()
        self.assertEqual(eff["tokens_total"], 0)


class TestSentinelAgentComplete(unittest.TestCase):
    def setUp(self):
        self._agent = SentinelAgentComplete("test_001", "demo")

    def test_init_ok(self):
        s = self._agent.status()
        self.assertEqual(s["client_id"], "test_001")
        self.assertGreater(s["phi_global"], 0)

    def test_pegasus_ip_blocked(self):
        alert = self._agent.process("5.199.174.88", 443, 1024)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["action"], "BLOCK")
        self.assertEqual(alert["tokens_used"], 0)

    def test_malicious_port_blocked(self):
        alert = self._agent.process("200.200.200.1", 4444, 512)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["action"], "BLOCK")

    def test_normal_no_alert(self):
        self._agent._profiler._ready = False
        alert = self._agent.process("10.0.0.1", 443, 1024)
        self.assertIsNone(alert)

    def test_counters_increment(self):
        n0 = self._agent._n_conn
        self._agent.process("10.0.0.1", 443, 512)
        self.assertEqual(self._agent._n_conn, n0+1)

    def test_threat_counter(self):
        n0 = self._agent._n_threat
        self._agent.process("5.199.174.88", 443, 512)
        self.assertGreater(self._agent._n_threat, n0)

    def test_simulate(self):
        alerts = self._agent.simulate(50)
        self.assertIsInstance(alerts, list)
        self.assertGreater(self._agent._n_conn, 0)

    def test_simulate_detects_threats(self):
        alerts = self._agent.simulate(200)
        self.assertGreater(len(alerts), 0)

    def test_simulate_zero_tokens(self):
        self._agent.simulate(100)
        eff = self._agent._orch.efficiency()
        self.assertEqual(eff["tokens_total"], 0)  # demo mode

    def test_simulate_target_met(self):
        self._agent.simulate(200)
        eff = self._agent._orch.efficiency()
        self.assertTrue(eff["target_met"])

    def test_block_unblock(self):
        self._agent._blocked.add("99.99.99.99")
        self.assertIn("99.99.99.99", self._agent._blocked)
        self._agent._blocked.discard("99.99.99.99")
        self.assertNotIn("99.99.99.99", self._agent._blocked)

    def test_false_positive(self):
        ok = self._agent.mark_false_positive("e1","10.0.0.5","admin")
        self.assertTrue(ok)

    def test_report_keys(self):
        self._agent.simulate(20)
        r = self._agent.report()
        for k in ["client_id","phi_current","connections",
                  "threats","orchestrator"]:
            self.assertIn(k, r)

    def test_status_keys(self):
        s = self._agent.status()
        for k in ["phi_global","health","coherent","connections",
                  "baseline","orch_efficiency"]:
            self.assertIn(k, s)

    def test_api_routes(self):
        from sentinel_agent_complete import create_api
        app = create_api(self._agent)
        with app.test_client() as c:
            r = c.get('/'); d = json.loads(r.data)
            self.assertIn("phi", d)

            r = c.get('/health'); d = json.loads(r.data)
            self.assertTrue(d["ok"])

            r = c.get('/status'); d = json.loads(r.data)
            self.assertIn("phi_global", d)

            r = c.post('/analyze',
                       data=json.dumps({"ip":"5.199.174.88","port":443}),
                       content_type='application/json')
            d = json.loads(r.data)
            self.assertIsNotNone(d["alert"])
            self.assertEqual(d["alert"]["action"], "BLOCK")
            self.assertEqual(d["alert"]["tokens_used"], 0)

            r = c.post('/simulate',
                       data=json.dumps({"n":50}),
                       content_type='application/json')
            d = json.loads(r.data)
            self.assertIn("llm_pct", d)
            self.assertTrue(d["target_met"])

            r = c.get('/efficiency'); d = json.loads(r.data)
            self.assertIn("llm_pct", d)

            r = c.get('/report'); d = json.loads(r.data)
            self.assertIn("connections", d)


def run_all():
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestPhi47Base, TestPhiGate, TestRuleEngine,
                TestDecisionCache, TestEfficientOrchestrator,
                TestSentinelAgentComplete]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    print(f"\n{'='*55}")
    print(f"  Sentinel-Agent Completo — Test Results")
    print(f"{'='*55}")
    print(f"  Total: {total} | Passed: {total-failed} | Failed: {failed}")
    for f in result.failures + result.errors:
        print(f"  FAIL: {f[0]}")
        print(f"  {f[1][-120:]}")
    print(f"  Result: {'ALL PASSED' if failed==0 else 'FAILURES'}")
    print(f"{'='*55}")
    return failed == 0

if __name__ == "__main__":
    run_all()
