![GitHub top language](https://img.shields.io/github/languages/top/cristianovisk/open_source_insights_api)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/open-source-insights-api)
![PyPI - Version](https://img.shields.io/pypi/v/open-source-insights-api)
![PyPI - Wheel](https://img.shields.io/pypi/wheel/open-source-insights-api)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cristianovisk/open_source_insights_api/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cristianovisk/open_source_insights_api)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7882/badge)](https://www.bestpractices.dev/projects/7882)
![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/y/cristianovisk/open_source_insights_api)
![GitHub Release Date - Published_At](https://img.shields.io/github/release-date/cristianovisk/open_source_insights_api)
![GitHub watchers](https://img.shields.io/github/watchers/cristianovisk/open_source_insights_api)
![GitHub User's stars](https://img.shields.io/github/stars/cristianovisk)
![CodeQL](https://github.com/cristianovisk/open_source_insights_api/workflows/CodeQL/badge.svg?branch=main)

![Logo](https://deps.dev/static/img/insights-logo-full-dark.efe5263f.svg)
# Open Source Insights Consume API

This library will consume data from project Google Open Source Insights. 

More information in [deps.dev](https://deps.dev "Website official Open Source Insights").

```shell
pip install open-source-insights-api
```
Example use CLI:
```shell
user@shell$ sbom_insights --help
usage: sbom_insights [-h] [-f [FILE]]

SBOM Insights

options:
  -h, --help            show this help message and exit
  -f [FILE], --file [FILE]
                        Define sbom.json to consume e return insights. (Default is sbom.json)
```
```shell
user@shell$ sbom_insights --file /opt/project/sbom.json
                                     SBOM Insights
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Package        ┃ Repository ┃ Version   ┃ Latest Version ┃ Dep Direct ┃ Dep Indirect ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ anyio          │ pypi       │ 4.0.0     │ 4.0.0          │ 3          │ 0            │
│ certifi        │ pypi       │ 2023.7.22 │ 2023.7.22      │ 0          │ 0            │
│ exceptiongroup │ pypi       │ 1.1.3     │ 1.1.3          │ 0          │ 0            │
│ h11            │ pypi       │ 0.14.0    │ 0.14.0         │ 0          │ 0            │
│ httpcore       │ pypi       │ 0.18.0    │ 0.18.0         │ 4          │ 2            │
│ httpx          │ pypi       │ 0.25.0    │ 0.25.0         │ 4          │ 3            │
│ idna           │ pypi       │ 3.4       │ 3.4.0          │ 0          │ 0            │
│ markdown-it-py │ pypi       │ 3.0.0     │ 3.0.0          │ 1          │ 0            │
│ mdurl          │ pypi       │ 0.1.2     │ 0.1.2          │ 0          │ 0            │
│ pygments       │ pypi       │ 2.15.1    │ 2.16.1         │ 0          │ 0            │
│ rich           │ pypi       │ 13.4.2    │ 13.5.3         │ 2          │ 1            │
│ sniffio        │ pypi       │ 1.3.0     │ 1.3.0          │ 0          │ 0            │
└────────────────┴────────────┴───────────┴────────────────┴────────────┴──────────────┘
```

Example use in code:

```python
from open_source_insights_api import os_insights

osi = os_insights.query()

#Will return all vulnerabilities in GHSA
vulns = osi.GetAdvisory('ghsa-xxxx-xxxx-xxxx') # ID vulnerability GHSA

#Will return all dependencies the package
deps = osi.GetDependencies('pypi', 'requests', '2.30.0') # Repository, Package, Version

#Will return simple info about the package
pkg = osi.GetPackage('pypi', 'requests') # Repository, Package

#Will return OpenSSF Scorecard and other info about repository in GitHub GitLab or BitBucket
project = osi.GetProject('github.com/owner/pkg')

#Will return all dependencies required to the package run
req = osi.GetRequirements('pypi', 'requests', '2.30.0')

#Will return information about especific version
version = osi.GetRequirements('pypi', 'requests', '2.30.0')

#Will search package in database of deps.dev
#Way one
result = osi.Search(system_repo="pypi", pkg_name="requests", pkg_version="2.30.0")
#Way two
result = osi.Search(hash_type="sha256", hash_value="57678e48b28e1be96ac260ad265ba84ace59cc5e098f65e28263363fa5f724c4")



```
