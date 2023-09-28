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

Example use:

```python
from open_source_insights_api import os_insights

apii = os_insights.query()

#Will return all vulnerabilities in GHSA
vulns = apii.GetAdvisory('ghsa-xxxx-xxxx-xxxx') # ID vulnerability GHSA

#Will return all dependencies the package
deps = apii.GetDependencies('pypi', 'requests', '2.30.0') # Repository, Package, Version

#Will return simple info about the package
pkg = apii.GetPackage('pypi', 'requests') # Repository, Package

#Will return OpenSSF Scorecard and other info about repository in GitHub GitLab or BitBucket
project = apii.GetProject('github.com/owner/pkg')

#Will return all dependencies required to the package run
req = apii.GetRequirements('pypi', 'requests', '2.30.0')

#Will return information about especific version
version = apii.GetRequirements('pypi', 'requests', '2.30.0')

#Will search package in database of deps.dev
#Way one
result = apii.Search(system_repo="pypi", pkg_name="requests", pkg_version="2.30.0")
#Way two
result = apii.Search(hash_type="sha256", hash_value="57678e48b28e1be96ac260ad265ba84ace59cc5e098f65e28263363fa5f724c4")



```
