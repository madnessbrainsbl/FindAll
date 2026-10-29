"""Tests for Grade detection, Salary parsing, and Deduplication in FindAll."""
import unittest
from jf.score import detect_grade, extract_salary, deduplicate_jobs


class JobIntelligenceTests(unittest.TestCase):
    def test_grade_detection_positive(self):
        self.assertEqual(detect_grade("Senior Backend Developer"), "senior")
        self.assertEqual(detect_grade("Lead Software Engineer"), "lead")
        self.assertEqual(detect_grade("Tech Lead - Core Infrastructure"), "lead")
        self.assertEqual(detect_grade("Head of Engineering"), "head")
        self.assertEqual(detect_grade("Junior Data Analyst"), "junior")
        self.assertEqual(detect_grade("Software Engineering Intern"), "intern")
        self.assertEqual(detect_grade("Старший разработчик Python"), "senior")
        self.assertEqual(detect_grade("Тимлид команды платформы"), "lead")

    def test_grade_detection_negative_marketing(self):
        # Must NOT trigger lead on marketing/sales phrases or common descriptions
        self.assertEqual(detect_grade("Lead Generation Specialist"), "")
        self.assertEqual(detect_grade("Sales Lead Representative"), "")
        self.assertEqual(
            detect_grade("Data Product Analyst", "Leading company in disruptive tech. You will lead initiatives."),
            "",
        )
        self.assertEqual(
            detect_grade("Marketing Associate", "Will lead to career growth and leadership opportunities."),
            "",
        )

    def test_salary_extraction_positive_ranges(self):
        s1 = extract_salary("Salary: $50–$125/hr for this role")
        self.assertIsNotNone(s1)
        self.assertEqual(s1["currency"], "USD")
        self.assertEqual(s1["min"], 50)
        self.assertEqual(s1["max"], 125)
        self.assertEqual(s1["period"], "hour")

        s2 = extract_salary("Compensation is $120k–$150k per year")
        self.assertIsNotNone(s2)
        self.assertEqual(s2["currency"], "USD")
        self.assertEqual(s2["min"], 120000)
        self.assertEqual(s2["max"], 150000)
        self.assertEqual(s2["period"], "year")

        s3 = extract_salary("Budget $80 - $120k")
        self.assertIsNotNone(s3)
        self.assertEqual(s3["currency"], "USD")
        self.assertEqual(s3["min"], 80000)
        self.assertEqual(s3["max"], 120000)
        self.assertEqual(s3["period"], "year")

        s4 = extract_salary("Offer: €60,000 / year")
        self.assertIsNotNone(s4)
        self.assertEqual(s4["currency"], "EUR")
        self.assertEqual(s4["min"], 60000)
        self.assertIsNone(s4["max"])
        self.assertEqual(s4["period"], "year")

        s5 = extract_salary("Вилка 250 000 - 350 000 руб/мес")
        self.assertIsNotNone(s5)
        self.assertEqual(s5["currency"], "RUB")
        self.assertEqual(s5["min"], 250000)
        self.assertEqual(s5["max"], 350000)
        self.assertEqual(s5["period"], "month")

    def test_salary_extraction_negative_funding_and_per_unit(self):
        # Corporate funding / valuation / total payouts must NEVER be parsed as salary
        self.assertIsNone(extract_salary("most recently raised $475M from The Carlyle Group at a valuation of over $1B"))
        self.assertIsNone(extract_salary("We have already paid out over $11M to our engineers."))
        self.assertIsNone(extract_salary("Company valued at $2B with revenue of $50M"))
        # Per-unit writing / token rates must not be parsed as annual/monthly salary
        self.assertIsNone(extract_salary("This equals approximately $30 or $17 per 500-word page"))
        self.assertIsNone(extract_salary("Initial compensation is up to $0.06 per word"))

    def test_telegram_extraction_and_classification(self):
        from jf.contacts import extract_telegrams, enrich
        text = (
            "Контакты: пишите в Telegram @anna_recruiter или в наш бот https://t.me/tech_hr_bot. "
            "Канал вакансий: https://t.me/s/best_tech_jobs. "
            "Код: @property @dataclass def run(): pass"
        )
        tgs = extract_telegrams(text)
        handles = {t["handle"]: t["kind"] for t in tgs}
        self.assertIn("@anna_recruiter", handles)
        self.assertEqual(handles["@anna_recruiter"], "tg_contact")
        self.assertIn("@tech_hr_bot", handles)
        self.assertEqual(handles["@tech_hr_bot"], "tg_bot")
        self.assertIn("@best_tech_jobs", handles)
        self.assertEqual(handles["@best_tech_jobs"], "tg_channel")
        # Decorators must never be extracted as telegram handles
        self.assertNotIn("@property", handles)
        self.assertNotIn("@dataclass", handles)

        enriched = enrich([{
            "title": "Backend Python",
            "company": "Acme Corp",
            "url": "https://example.com/job/1",
            "description": "Email: jobs@acme.com or TG: @acme_talent",
            "source": "remoteok",
        }])
        self.assertIn("jobs@acme.com", enriched["jobs"][0]["found_emails"])
        self.assertIn("@acme_talent", enriched["jobs"][0]["found_emails"])
        emails_list = [e["email"] for e in enriched["emails"]]
        self.assertIn("jobs@acme.com", emails_list)
        self.assertIn("@acme_talent", emails_list)

    def test_skill_highlighting_in_html_and_markdown(self):
        import tempfile
        from pathlib import Path
        from jf import report, score as score_mod

        job = {
            "title": "Senior Python Developer",
            "company": "Tech Innovators",
            "url": "https://example.com/job/1",
            "location": "Remote",
            "remote": True,
            "description": "Looking for Python, FastAPI, and Docker expertise. PostgreSQL is a plus.",
            "source": "remoteok",
            "found_emails": "hr@innovators.example",
            "matched_skills": ["python", "fastapi", "docker"],
        }
        data = {
            "jobs": [job],
            "emails": [{"email": "hr@innovators.example", "company": "Tech Innovators", "source": "remoteok", "job_url": job["url"]}],
            "links": [],
            "generated": "2026-10-08",
        }
        with tempfile.TemporaryDirectory() as tmp:
            html_p = report.write_html_report(Path(tmp) / "report.html", data)
            html_content = html_p.read_text(encoding="utf-8")
            self.assertIn("b-skill", html_content)
            self.assertIn(">python<", html_content)
            self.assertIn(">fastapi<", html_content)

            md_p = report.write_markdown(Path(tmp) / "report.md", data)
            md_content = md_p.read_text(encoding="utf-8")
            self.assertIn("Skills", md_content)
            self.assertIn("python, fastapi, docker", md_content)

    def test_circuit_breaker(self):
        import time
        from jf.resilience import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        self.assertTrue(cb.is_available("flaky_board"))

        # 1st failure — still available
        tripped = cb.record_failure("flaky_board", "HTTP 403")
        self.assertFalse(tripped)
        self.assertTrue(cb.is_available("flaky_board"))

        # 2nd failure — trips OPEN
        tripped = cb.record_failure("flaky_board", "HTTP 403")
        self.assertTrue(tripped)
        self.assertFalse(cb.is_available("flaky_board"))

        # Other sources are independent
        self.assertTrue(cb.is_available("good_board"))
        cb.record_success("good_board")
        self.assertTrue(cb.is_available("good_board"))

        # Half-open recovery after timeout
        time.sleep(0.12)
        self.assertTrue(cb.is_available("flaky_board"))

    def test_telegram_digest_formatting_and_credentials(self):
        from jf import notify

        # Credential resolution
        prof = {"telegram_bot_token": "123:TOKEN", "telegram_chat_id": "@my_channel"}
        t, c = notify.resolve_telegram_credentials(profile=prof)
        self.assertEqual(t, "123:TOKEN")
        self.assertEqual(c, "@my_channel")

        # Missing credentials rejection
        ok, err = notify.send_telegram("", "", "test")
        self.assertFalse(ok)
        self.assertIn("missing", err)

        # Digest formatting
        sample_jobs = [
            {
                "title": "Lead Python Engineer",
                "company": "FastTech",
                "score": 85,
                "url": "https://fasttech.example/jobs/1",
                "location": "Global",
                "remote": True,
                "grade": "lead",
                "salary": {"raw": "$120k–$150k"},
                "matched_skills": ["python", "fastapi"],
                "found_emails": "@recruiter_nick",
            },
            {
                "title": "Junior Developer",
                "company": "SmallCo",
                "score": 40,
                "url": "https://smallco.example/jobs/2",
            },
        ]
        digest = notify.format_top_jobs_digest(sample_jobs, profile_name="Backend", top_n=5, min_score=60)
        self.assertIn("FindAll", digest)
        self.assertIn("Lead Python Engineer", digest)
        self.assertIn("FastTech", digest)
        self.assertIn("85/100", digest)
        self.assertIn("$120k–$150k", digest)
        self.assertIn("python", digest)
        self.assertIn("https://fasttech.example/jobs/1", digest)
        # Junior developer with score 40 must not be included (min_score=60)
        self.assertNotIn("SmallCo", digest)


if __name__ == "__main__":
    unittest.main()
