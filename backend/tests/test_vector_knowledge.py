"""BharatSec AI knowledge base on MongoDB Atlas Vector Search: sync, retrieval, citations and admin endpoints."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import auth as auth_service
from engines import ai_engine, llm, threat_intel_engine, vector_knowledge
from tests.auth_helpers import authenticated_client


class FakeCollection:
    """The slice of a pymongo collection the knowledge base uses."""

    def __init__(self):
        self.docs = {}
        self.indexes = []
        self.pipelines = []
        self.results = []

    def find(self, query, projection):
        return [{"_id": key, **{field: doc.get(field) for field in projection}} for key, doc in self.docs.items()]

    def delete_many(self, query):
        for key in query["_id"]["$in"]:
            self.docs.pop(key, None)

    def replace_one(self, selector, document, upsert=False):
        self.docs[selector["_id"]] = document

    def list_search_indexes(self, name):
        return [index for index in self.indexes if index["name"] == name]

    def create_search_index(self, model):
        self.indexes.append({**model.document, "status": "PENDING"})

    def aggregate(self, pipeline):
        self.pipelines.append(pipeline)
        return list(self.results)

    def count_documents(self, query):
        return sum(1 for doc in self.docs.values() if doc.get("embed_model") == query.get("embed_model"))


def _note(note_id, text="Some text"):
    return {"id": note_id, "title": f"Title {note_id}", "source": "Test", "url": "", "text": text,
            "hash": f"hash-{note_id}-{text}"}


def _fake_embed(calls):
    async def embed(texts, kind):
        calls.append((len(texts), kind))
        return [[0.1] * vector_knowledge.DIMENSIONS for _ in texts]
    return embed


class KnowledgeSyncTests(unittest.TestCase):
    def setUp(self):
        self.collection = FakeCollection()
        self.patches = [
            patch.object(vector_knowledge, "MONGODB_URI", "mongodb+srv://example"),
            patch.object(vector_knowledge, "GEMINI_API_KEY", "g"),
            patch.object(vector_knowledge, "VOYAGE_API_KEY", ""),
            patch.object(vector_knowledge, "_collection", return_value=self.collection),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()

    def test_sync_embeds_new_notes_once_removes_retired_ones_and_creates_the_index(self):
        self.collection.docs["old"] = {"_id": "old", "hash": "x", "embed_model": "gemini-embedding-001"}
        calls = []
        with patch.object(vector_knowledge, "collect_notes", return_value=[_note("a"), _note("b")]), \
             patch.object(vector_knowledge, "embed", _fake_embed(calls)):
            first = asyncio.run(vector_knowledge.sync())
            second = asyncio.run(vector_knowledge.sync())

        self.assertEqual(first["embedded"], 2)
        self.assertEqual(first["removed"], 1)
        self.assertEqual(first["index"], "PENDING")
        self.assertEqual(second["embedded"], 0)
        self.assertEqual(calls, [(2, "document")])
        self.assertEqual(set(self.collection.docs), {"a", "b"})
        stored = self.collection.docs["a"]
        self.assertEqual(stored["embed_model"], "gemini-embedding-001")
        self.assertEqual(len(stored["embedding"]), vector_knowledge.DIMENSIONS)
        index = self.collection.indexes[0]
        self.assertEqual(index["name"], vector_knowledge.INDEX_NAME)
        self.assertEqual(index["type"], "vectorSearch")
        self.assertEqual(index["definition"]["fields"][0]["numDimensions"], vector_knowledge.DIMENSIONS)

    def test_changed_text_or_a_new_embedding_model_re_embeds(self):
        calls = []
        with patch.object(vector_knowledge, "collect_notes", return_value=[_note("a")]), \
             patch.object(vector_knowledge, "embed", _fake_embed(calls)):
            asyncio.run(vector_knowledge.sync())
        with patch.object(vector_knowledge, "collect_notes", return_value=[_note("a", "Updated")]), \
             patch.object(vector_knowledge, "embed", _fake_embed(calls)):
            asyncio.run(vector_knowledge.sync())
        with patch.object(vector_knowledge, "VOYAGE_API_KEY", "v"), \
             patch.object(vector_knowledge, "collect_notes", return_value=[_note("a", "Updated")]), \
             patch.object(vector_knowledge, "embed", _fake_embed(calls)):
            result = asyncio.run(vector_knowledge.sync())
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["embed_model"], "voyage-4")
        self.assertEqual(self.collection.docs["a"]["embed_model"], "voyage-4")

    def test_quota_error_pauses_and_leaves_the_rest_for_the_next_run(self):
        notes = [_note(str(number)) for number in range(vector_knowledge.EMBED_BATCH + 5)]
        replies = [None, vector_knowledge.EmbeddingError("Gemini embeddings failed: HTTP 429", retry_later=True)]

        async def embed(texts, kind):
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return [[0.2] * vector_knowledge.DIMENSIONS for _ in texts]

        with patch.object(vector_knowledge, "collect_notes", return_value=notes), \
             patch.object(vector_knowledge, "embed", embed):
            result = asyncio.run(vector_knowledge.sync())
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["embedded"], vector_knowledge.EMBED_BATCH)
        self.assertEqual(result["remaining"], 5)
        self.assertIn("429", result["detail"])

    def test_retrieve_searches_only_this_models_vectors_and_drops_weak_matches(self):
        self.collection.results = [
            {"title": "CERT-In Directions", "text": "Report within 6 hours.", "source": "CERT-In", "url": "https://www.cert-in.org.in", "score": 0.84},
            {"title": "Unrelated", "text": "Noise.", "source": "Test", "url": "", "score": 0.4},
        ]
        with patch.object(vector_knowledge, "embed", _fake_embed([])):
            notes = asyncio.run(vector_knowledge.retrieve("When must we report an incident to CERT-In?"))
        self.assertEqual([note["title"] for note in notes], ["CERT-In Directions"])
        stage = self.collection.pipelines[0][0]["$vectorSearch"]
        self.assertEqual(stage["index"], vector_knowledge.INDEX_NAME)
        self.assertEqual(stage["filter"], {"embed_model": "gemini-embedding-001"})

    def test_retrieve_never_raises(self):
        async def broken(texts, kind):
            raise vector_knowledge.EmbeddingError("down")

        with patch.object(vector_knowledge, "embed", broken):
            self.assertEqual(asyncio.run(vector_knowledge.retrieve("What is the DPDP Act penalty?")), [])
        self.assertEqual(asyncio.run(vector_knowledge.retrieve("hi")), [])  # too short to be worth a search


class KnowledgeOffTests(unittest.TestCase):
    def test_without_mongodb_nothing_is_searched(self):
        with patch.object(vector_knowledge, "MONGODB_URI", ""):
            self.assertFalse(vector_knowledge.configured())
            self.assertEqual(asyncio.run(vector_knowledge.retrieve("What does CERT-In require?")), [])
            self.assertEqual(asyncio.run(vector_knowledge.sync()), {"status": "disabled"})


class KnowledgeNotesTests(unittest.TestCase):
    def test_notes_cover_india_law_fix_guides_offline_answers_and_kev(self):
        kev = [{"cve": "CVE-2026-0001", "name": "Example RCE", "products": ["Acme", "Gateway"],
                "ransomware": True, "date_added": "2026-10-01"}]
        with patch.object(threat_intel_engine, "recent_kev_entries", return_value=kev):
            notes = vector_knowledge.collect_notes()
        ids = {note["id"] for note in notes}
        self.assertIn("india:cert-in-directions-2022", ids)
        self.assertIn("finding:no_dmarc", ids)
        self.assertTrue(any(note_id.startswith("offline:") for note_id in ids))
        kev_note = next(note for note in notes if note["id"] == "kev:CVE-2026-0001")
        self.assertIn("ransomware", kev_note["text"])
        self.assertTrue(kev_note["url"].endswith("CVE-2026-0001"))
        self.assertEqual(len(ids), len(notes), "note ids must be unique")
        for note in notes:
            self.assertNotIn(chr(0x2014), note["title"] + note["text"])  # house style: no em dashes
            self.assertEqual(len(note["hash"]), 64)


class CitedAnswerTests(unittest.TestCase):
    NOTE = {"title": "CERT-In Directions", "text": "Report within 6 hours.", "source": "CERT-In",
            "url": "https://www.cert-in.org.in/Directions70B.jsp", "score": 0.9}

    def test_stream_puts_notes_in_the_prompt_and_references_in_meta(self):
        seen = {}

        async def fake_stream(providers, system, messages, **kwargs):
            seen["system"] = system
            yield "provider", llm.Provider("gemini", "k", "gemini-3.8-flash")
            yield "delta", "Report within 6 hours [1]."

        async def go():
            return [event async for event in ai_engine.general_ai_stream("When do I report to CERT-In?")]

        with patch.object(ai_engine, "GEMINI_API_KEY", "g"), \
             patch.object(ai_engine.vector_knowledge, "retrieve", AsyncMock(return_value=[self.NOTE])), \
             patch.object(ai_engine.llm, "stream", fake_stream):
            events = asyncio.run(go())
        self.assertIn("<reference_notes>", seen["system"])
        self.assertIn("[1] CERT-In Directions (CERT-In)", seen["system"])
        self.assertEqual(events[0]["references"], [
            {"n": 1, "title": "CERT-In Directions", "source": "CERT-In", "url": "https://www.cert-in.org.in/Directions70B.jsp"},
        ])

    def test_offline_mode_skips_retrieval(self):
        retrieve = AsyncMock(return_value=[self.NOTE])

        async def go():
            return [event async for event in ai_engine.general_ai_stream("How do I report UPI fraud?")]

        with patch.object(ai_engine, "GEMINI_API_KEY", ""), patch.object(ai_engine, "OPENAI_API_KEY", ""), \
             patch.object(ai_engine.vector_knowledge, "retrieve", retrieve):
            events = asyncio.run(go())
        retrieve.assert_not_called()
        self.assertEqual(events[0]["source"], "rules")


class KnowledgeAdminApiTests(unittest.TestCase):
    def setUp(self):
        self.client = authenticated_client()  # the first account is the administrator

    def tearDown(self):
        self.client.close()

    def test_status_reports_disabled_without_mongodb(self):
        with patch.object(vector_knowledge, "MONGODB_URI", ""):
            response = self.client.get("/api/ai/knowledge")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["enabled"])

    def test_sync_endpoint_runs_a_sync(self):
        sync = AsyncMock(return_value={"status": "ok", "embedded": 3})
        with patch.object(vector_knowledge, "sync", sync):
            response = self.client.post("/api/ai/knowledge/sync")
        self.assertEqual(response.json(), {"status": "ok", "embedded": 3})

    def test_analysts_cannot_manage_the_knowledge_base(self):
        from fastapi import HTTPException
        from routers import ai as ai_router

        class Request:
            class state:
                user = {"id": 99, "role": "analyst"}

        with self.assertRaises(HTTPException) as caught:
            ai_router._require_admin(Request())
        self.assertEqual(caught.exception.status_code, 403)


class CronKnowledgeTests(unittest.TestCase):
    def test_cron_tick_syncs_the_knowledge_base_when_configured(self):
        client = authenticated_client()
        try:
            with auth_service._database() as connection:
                connection.execute("DELETE FROM app_settings WHERE key LIKE 'job:%'")
            from engines import soc_engine
            sync = AsyncMock(return_value={"status": "ok", "embedded": 4})
            with patch.object(soc_engine, "list_due_assets", return_value=[]), \
                 patch.object(threat_intel_engine, "sync_feeds", AsyncMock(return_value=[])), \
                 patch.object(threat_intel_engine, "sync_breach_watches", AsyncMock()), \
                 patch.object(vector_knowledge, "configured", return_value=True), \
                 patch.object(vector_knowledge, "sync", sync):
                body = client.get("/api/cron/tick").json()
            self.assertEqual(body["knowledge"], {"status": "ok", "embedded": 4})
            sync.assert_awaited_once()
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
