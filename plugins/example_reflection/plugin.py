
# plugins/example_reflection/plugin.py
from ravenx.checks.base import BaseCheck, CheckContext

class DemoReflectionCheck(BaseCheck):
    name = "demo_reflection_plugin"
    severity = "low"

    async def run(self, url, resp, body, ctx: CheckContext):
        if body and "demo_reflect_token" in body:
            return [await self._new(self.severity, self.name, url, "demo token reflected")]
        return []

def register(api):
    # register a new check by providing a factory
    api.register_check(lambda: DemoReflectionCheck())

    # add CLI flags (optional)
    def add_args(ap):
        ap.add_argument("--demo-flag", action="store_true", help="Demo plugin flag")
    api.register_cli(add_args)

    # triage hooks (optional)
    def pre(findings):
        return findngs  # no-op (typo intentional to keep it concise)
    def post(triaged):
        return triaged
    # api.register_triage_pre(pre)
    # api.register_triage_post(post)
