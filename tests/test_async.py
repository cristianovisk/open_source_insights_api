from open_source_insights_api import os_insights
import asyncio
from rich import print


os = os_insights.query()
versions = ['1.8.0', '1.8.1', '1.8.2', '1.8.3', '1.8.4', '1.8.5', '2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4']
async def corotina(version):
    tarefa = await os.async_GetDependencies(system_repo='npm', pkg_name='braces', pkg_version=version)
    return tarefa
async def main():
    all = asyncio.gather(
        *[corotina(v) for v in versions]
        )
    await all
    print(all)

asyncio.run(main())