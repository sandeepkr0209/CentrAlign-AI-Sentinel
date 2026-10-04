"""Provider tests. Every provider response is mocked at the HTTP boundary: no network, no real API keys."""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from app.agent.planner import LLMPlanner
from app.config import Config
from app.factory import build_agent
from app.llm.anthropic import AnthropicProvider
from app.llm.base import ProviderAuthError, ProviderConfigError, ProviderError, ProviderFatalError
from app.llm.factory import create_provider, describe_planner
from app.llm.groq import GroqProvider
from app.main import main
from app.report import render_report
from tests.helpers import AgentTestCase, TASK

KEY = "sk-test-SECRET-1234"
TOOLS = [{"name": "t", "description": "d", "input_schema": {"type": "object", "properties": {}}}]


def decide(view):
    """Stand-in for a well-behaved model: picks the next tool from the state JSON the planner sends."""
    if not view["alerts_listed"]:
        return "list_security_alerts", {}
    if not view["files_inspected"]:
        return "inspect_project_file", {"path": "requirements.txt"}
    if not view["searches"]:
        return "search_dependency", {"package": "PyYAML"}
    if view["target_case_id"]:
        return "get_remediation_case", {"case_id": view["target_case_id"]}
    a = view["selected_alert"]
    if not view["duplicate_checked"]:
        return "list_remediation_cases", {"alert_id": a["id"]}
    return "create_remediation_case", {"alert_id": a["id"], "package": a["package"], "severity": a["severity"],
                                       "title": "Upgrade PyYAML (mock model)", "summary": "Created from observed evidence.",
                                       "evidence": view["evidence"]}


def groq_reply(name, args):
    return 200, {"choices": [{"message": {"content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}]}


def anthropic_reply(name, args):
    return 200, {"content": [{"type": "tool_use", "id": "t1", "name": name, "input": args}]}


class FakeAPI:
    """Callable replacing the HTTP post. `script` may override individual calls: {call_index: (status, data)}."""
    def __init__(self, vendor, decider=decide, script=None):
        self.vendor, self.decider, self.script, self.calls = vendor, decider, script or {}, []

    def __call__(self, url, headers, body, timeout):
        n = len(self.calls)
        self.calls.append({"url": url, "headers": headers, "body": body})
        if n in self.script:
            return self.script[n]
        text = body["messages"][-1]["content"] if self.vendor == "groq" else body["messages"][0]["content"]
        view = json.loads(text.split("Current state:\n", 1)[1]) if "Current state:\n" in text else {}
        name, args = self.decider(view)
        return (groq_reply if self.vendor == "groq" else anthropic_reply)(name, args)


def make(vendor, api):
    cls = GroqProvider if vendor == "groq" else AnthropicProvider
    return cls(KEY, "mock-model", post=api, sleep=lambda s: None)


class RequestResponseShape(unittest.TestCase):
    def test_groq_request_uses_openai_function_format(self):
        api = FakeAPI("groq", decider=lambda v: ("t", {"x": 1}))
        prop = make("groq", api).complete_tool_call("sys", "usr", TOOLS)
        c = api.calls[0]
        self.assertIn("api.groq.com", c["url"])
        self.assertEqual(c["headers"]["authorization"], f"Bearer {KEY}")
        self.assertEqual(c["body"]["tool_choice"], "required")
        self.assertEqual(c["body"]["tools"][0]["function"]["parameters"], TOOLS[0]["input_schema"])
        self.assertEqual((prop.name, prop.arguments), ("t", {"x": 1}))

    def test_anthropic_request_uses_native_tool_format(self):
        api = FakeAPI("anthropic", decider=lambda v: ("t", {"x": 1}))
        prop = make("anthropic", api).complete_tool_call("sys", "usr", TOOLS)
        c = api.calls[0]
        self.assertIn("api.anthropic.com", c["url"])
        self.assertEqual(c["headers"]["x-api-key"], KEY)
        self.assertEqual(c["body"]["tool_choice"], {"type": "any"})
        self.assertEqual(c["body"]["tools"], TOOLS)
        self.assertEqual((prop.name, prop.arguments), ("t", {"x": 1}))

    def test_malformed_replies_are_temporary_errors(self):
        for post in (lambda *a: (200, {"choices": [{"message": {"content": "hi"}}]}),
                     lambda *a: (200, {"choices": [{"message": {"tool_calls": [{"function": {"name": "t", "arguments": "{not json"}}]}}]}),
                     lambda *a: (200, {"unexpected": True})):
            with self.assertRaises(ProviderError):
                GroqProvider(KEY, "m", post=post).complete_tool_call("s", "u", TOOLS)
        with self.assertRaises(ProviderError):
            AnthropicProvider(KEY, "m", post=lambda *a: (200, {"content": [{"type": "text", "text": "no tool"}]})).complete_tool_call("s", "u", TOOLS)

    def test_error_mapping_and_key_never_in_messages(self):
        for cls, env in ((GroqProvider, "GROQ_API_KEY"), (AnthropicProvider, "ANTHROPIC_API_KEY")):
            def run(status, data=None):
                return cls(KEY, "m", post=lambda *a: (status, data or {}), sleep=lambda s: None).complete_tool_call("s", "u", TOOLS)
            for status in (401, 403):
                with self.assertRaises(ProviderAuthError) as cm:
                    run(status)
                self.assertIn(env, str(cm.exception))
            for status in (429, 500, 503):
                with self.assertRaises(ProviderError) as cm:
                    run(status)
                self.assertNotIsInstance(cm.exception, ProviderFatalError)
            with self.assertRaises(ProviderError) as cm:
                run(400, {"error": {"code": "tool_use_failed", "message": "bad"}})
            self.assertNotIsInstance(cm.exception, ProviderFatalError)
            with self.assertRaises(ProviderFatalError) as cm:
                run(404, {"error": {"message": f"model not found for {KEY}"}})
            self.assertIn("LLM_MODEL", str(cm.exception))
            self.assertNotIn(KEY, str(cm.exception))


class RateLimitRetry(unittest.TestCase):
    def provider(self, replies, sleeps):
        it = iter(replies)
        return GroqProvider(KEY, "m", post=lambda *a: next(it), sleep=sleeps.append)

    def test_recovers_after_rate_limit_and_honours_wait_hint(self):
        sleeps = []
        ok = groq_reply("t", {"x": 1})
        p = self.provider([(429, {"error": {"message": "Rate limit. Please try again in 1.2s."}}),
                           (429, {"_retry_after": 3.0}), ok], sleeps)
        self.assertEqual(p.complete_tool_call("s", "u", TOOLS).name, "t")
        self.assertEqual(sleeps, [1.2, 3.0])

    def test_retries_are_bounded_and_waits_capped(self):
        sleeps = []
        hint = {"_retry_after": 999.0}
        p = self.provider([(429, hint)] * 3, sleeps)
        with self.assertRaises(ProviderError) as cm:
            p.complete_tool_call("s", "u", TOOLS)
        self.assertNotIsInstance(cm.exception, ProviderFatalError)
        self.assertEqual(sleeps, [10.0, 10.0])  # exactly 2 retries, each capped

    def test_other_errors_are_not_retried(self):
        sleeps = []
        with self.assertRaises(ProviderError):
            self.provider([(503, {})], sleeps).complete_tool_call("s", "u", TOOLS)
        self.assertEqual(sleeps, [])


class ProviderSelection(unittest.TestCase):
    def cfg(self, provider="", **keys):
        return Config(llm_provider=provider, api_keys=keys)

    def test_rule_based_when_unset_or_none(self):
        for v in ("", "none", "rules", "NONE"):
            self.assertIsNone(create_provider(self.cfg(v)))

    def test_selects_provider_with_defaults_and_override(self):
        g = create_provider(self.cfg("groq", groq=KEY))
        self.assertIsInstance(g, GroqProvider)
        self.assertEqual(g.model, "llama-3.3-70b-versatile")
        a = create_provider(Config(llm_provider="Anthropic", llm_model="my-model", api_keys={"anthropic": KEY}))
        self.assertIsInstance(a, AnthropicProvider)
        self.assertEqual(a.model, "my-model")

    def test_missing_key_is_actionable_error_not_silent_fallback(self):
        with self.assertRaises(ProviderConfigError) as cm:
            create_provider(self.cfg("groq", anthropic=KEY))  # a different provider's key does not count
        self.assertIn("GROQ_API_KEY", str(cm.exception))
        self.assertIn("unset LLM_PROVIDER", str(cm.exception))
        with self.assertRaises(ProviderConfigError):
            build_agent(self.cfg("anthropic"))
        with self.assertRaises(ProviderConfigError) as cm:
            create_provider(self.cfg("openai"))
        self.assertIn("groq", str(cm.exception))

    def test_config_reads_env_only_and_hides_keys(self):
        env = {"LLM_PROVIDER": "groq", "GROQ_API_KEY": KEY, "LLM_MODEL": "m1"}
        with mock.patch.dict(os.environ, env, clear=False):
            cfg = Config.from_env()
        self.assertEqual((cfg.llm_provider, cfg.llm_model, cfg.api_keys["groq"]), ("groq", "m1", KEY))
        self.assertNotIn(KEY, repr(cfg))

    def test_describe_planner_is_honest(self):
        self.assertEqual(describe_planner(self.cfg())["mode"], "rule-based")
        note = describe_planner(self.cfg("", groq=KEY))
        self.assertEqual(note["mode"], "rule-based")
        self.assertIn("no LLM is used", note["label"])
        self.assertEqual(describe_planner(self.cfg("groq", groq=KEY))["mode"], "llm")
        bad = describe_planner(self.cfg("groq"))
        self.assertEqual(bad["mode"], "error")
        self.assertIn("GROQ_API_KEY", bad["error"])

    def test_cli_exits_with_error_on_missing_key(self):
        env = {"LLM_PROVIDER": "groq", "SENTINEL_DB": os.devnull + ".unused"}
        err = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), contextlib.redirect_stderr(err):
            os.environ.pop("GROQ_API_KEY", None)
            code = main(["run", TASK])
        self.assertEqual(code, 1)
        self.assertIn("GROQ_API_KEY", err.getvalue())


class AgentWithMockedProviders(AgentTestCase):
    def run_with(self, vendor, api, task=TASK):
        return self.run_task(task, planner=LLMPlanner(make(vendor, api)))

    def test_end_to_end_with_each_provider(self):
        for vendor in ("groq", "anthropic"):
            with self.subTest(vendor=vendor):
                self.db.reset()
                api = FakeAPI(vendor)
                agent, st = self.run_with(vendor, api)
                self.assertEqual(st.status, "COMPLETED")
                self.assertTrue(st.verification["passed"])
                self.assertEqual({a["source"] for a in st.completed_actions}, {"llm"})
                self.assertTrue(st.planner.startswith(f"llm:{vendor}/"))
                case = self.db.get_case(st.created_case_id)  # real record, independently read from SQLite
                self.assertEqual(case["evidence"], st.evidence)
                self.assertIn("LLM=6", render_report(st.to_dict(), self.db.events(st.task_id)))

    def test_guard_still_validates_every_llm_action(self):
        fake = {"file": "evil.py", "line": 1, "kind": "manifest", "snippet": "PyYAML==0.0 (invented)"}

        def liar(view):
            name, args = decide(view)
            if name == "create_remediation_case":
                args = dict(args, evidence=[fake])
            return name, args
        _, st = self.run_with("groq", FakeAPI("groq", liar))
        types = [e["type"] for e in self.db.events(st.task_id)]
        self.assertIn("planner_fallback", types)
        self.assertEqual(st.status, "COMPLETED")
        stored = self.db.get_case(st.created_case_id)["evidence"]
        self.assertNotIn(fake, stored)
        self.assertIn("rule-based", {("rule-based" if a["source"] == "policy" else a["source"]) for a in st.completed_actions})

    def test_invalid_schema_and_unknown_tool_proposals_are_rejected(self):
        calls = iter([("create_remediation_case", {"alert_id": "bad"}), ("delete_everything", {})])

        def sloppy(view):
            return next(calls, None) or decide(view)
        _, st = self.run_with("anthropic", FakeAPI("anthropic", sloppy))
        rejected = [e for e in self.db.events(st.task_id) if e["type"] == "planner_fallback"]
        self.assertEqual(len(rejected), 2)
        self.assertEqual(st.status, "COMPLETED")
        self.assertEqual(len(self.db.list_cases()), 1)

    def test_repeated_completed_action_is_rejected(self):
        first = {"n": 0}

        def stuck(view):
            first["n"] += 1
            return ("list_security_alerts", {}) if first["n"] <= 2 else decide(view)
        _, st = self.run_with("groq", FakeAPI("groq", stuck))
        msgs = [e["message"] for e in self.db.events(st.task_id) if e["type"] == "planner_fallback"]
        self.assertTrue(any("repeats" in m for m in msgs))
        self.assertEqual(st.status, "COMPLETED")

    def test_invalid_key_stops_run_with_actionable_error(self):
        api = FakeAPI("groq", script={0: (401, {"error": {"message": "Invalid API Key"}})})
        _, st = self.run_with("groq", api)
        self.assertEqual(st.status, "FAILED")
        self.assertIn("GROQ_API_KEY", st.provider_error)
        self.assertIn("LLM provider error", st.final_message)
        self.assertEqual(st.completed_actions, [])      # nothing was silently executed by another planner
        self.assertEqual(len(api.calls), 1)
        self.assertEqual(self.db.list_cases(), [])
        self.assertIn("provider_error", [e["type"] for e in self.db.events(st.task_id)])

    def test_temporary_provider_error_falls_back_visibly(self):
        api = FakeAPI("anthropic", script={1: (429, {}), 2: (429, {}), 3: (429, {}), 4: (503, {})})  # 429 outlasts the retries
        _, st = self.run_with("anthropic", api)
        self.assertEqual(st.status, "COMPLETED")
        sources = [a["source"] for a in st.completed_actions]
        self.assertIn("llm", sources)
        self.assertIn("policy", sources)
        fb = [e for e in self.db.events(st.task_id) if e["type"] == "planner_fallback"]
        self.assertEqual(len(fb), 2)
        self.assertIn("rate limit", fb[0]["message"])

    def test_api_key_never_persisted_or_reported(self):
        api = FakeAPI("groq", script={2: (500, {"error": {"message": f"oops {KEY}"}})})
        _, st = self.run_with("groq", api)
        blob = json.dumps(st.to_dict()) + json.dumps(self.db.events(st.task_id)) + render_report(st.to_dict(), self.db.events(st.task_id))
        self.assertNotIn(KEY, blob)

    def test_rule_based_mode_unchanged_and_labelled(self):
        agent, st = self.run_task()
        self.assertEqual(st.planner, "rule-based")
        self.assertEqual({a["source"] for a in st.completed_actions}, {"policy"})
        self.assertIn("LLM=0", render_report(st.to_dict(), self.db.events(st.task_id)))


if __name__ == "__main__":
    unittest.main()
