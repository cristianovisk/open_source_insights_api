import httpx as requests
from httpx import AsyncClient
import json
import urllib.parse
from functools import cache

class query:
    """The Deps.dev Insights API provides information about open source software
    packages, projects, and security advisories. The information is gathered
    from upstream services like npm, GitHub, and OSV, and augmented by computing
    dependencies and relationships between entities.
    """
    def __init__(self) -> None:
        self.systems = [
            "GO",
            "NPM",
            "CARGO",
            "MAVEN",
            "PYPI",
            "NUGET",
            "github.com",
            "gitlab.com",
            "bitbucket.org"
        ]

        self.hashs = [
            "MD5",
            "SHA1",
            "SHA256",
            "SHA512"
        ]

    def __CheckSupportedSystem(self, system_repo):
        system_repo = system_repo.upper()
        flag = False

        for system in self.systems:
            if system_repo == system:
                flag = True
        
        return flag
    
    def __CheckSupportedHashs(self, hash_type):
        hash_type = hash_type.upper()
        flag = False

        for hash in self.hashs:
            if hash_type == hash:
                flag = True
        
        return flag
    
    def __CheckSupportedRepo(self, system_repo):
        system_repo = system_repo.split('/', 1)[0]
        flag = False

        for system in self.systems:
            if system_repo == system:
                flag = True
        
        return flag
# Functions Syncs
    @cache
    def GetPackage(self, system_repo, pkg_name):
        """GetPackage returns information about a package, including a list of its
        available versions, with the default version marked if known.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    def GetVersion(self, system_repo, pkg_name, pkg_version):
        """GetVersion returns information about a specific package version, including
        its licenses and any security advisories known to affect it.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    def GetRequirements(self, system_repo, pkg_name, pkg_version):
        """GetRequirements returns the requirements for a given version in a
        system-specific format. Requirements are currently only available for
        NuGet.

        Requirements are the dependency constraints specified by the version.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}

            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache   
    def GetDependencies(self, system_repo, pkg_name, pkg_version):
        """GetDependencies returns a resolved dependency graph for the given package
        version. Dependencies are currently available for Go, npm, Cargo, Maven
        and PyPI.

        Dependencies are the resolution of the requirements (dependency
        constraints) specified by a version.

        The dependency graph should be similar to one produced by installing the
        package version on a generic 64-bit Linux system, with no other
        dependencies present. The precise meaning of this varies from system to
        system.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    def GetProject(self, repo): # ex github.com/owner/pkg
        """GetProject returns information about projects hosted by GitHub, GitLab, or
        BitBucket, when known to us.
        """
        if self.__CheckSupportedRepo(repo):
            repo = urllib.parse.quote_plus(repo)
            
            url = f'https://api.deps.dev/v3alpha/projects/{repo.lower()}'

            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}

            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    def GetAdvisory(self, advisor_id): # ex GHSA-xxxx-xxxx-xxxx
        """GetAdvisory returns information about security advisories hosted by OSV.
        """
        if advisor_id.split('-', 1)[0] == "GHSA":
            
            url = f'https://api.deps.dev/v3alpha/advisories/{advisor_id}'

            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}"}

            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404"}
            
            return r_json
        else:
            return {"error": "Advisor ID no supported", "example": "GHSA-xxxx-xxxx-xxxx"}
    @cache 
    def Search(self, system_repo=None, pkg_name=None, pkg_version=None, hash_type=None, hash_value=None): # ex GHSA-xxxx-xxxx-xxxx
        """Query returns information about multiple package versions, which can be
        specified by name, content hash, or both.

        It is typical for hash queries to return many results; hashes are matched
        against multiple release artifacts (such as JAR files) that comprise
        package versions, and any given artifact may appear in many package
        versions.
        """
        url = f'https://api.deps.dev/v3alpha/query'

        if hash_type != None and hash_value != None and self.__CheckSupportedHashs(hash_type):
            hash_value = urllib.parse.quote_plus(hash_value)
            params = {
                "hash.type": hash_type,
                "hash.value": hash_value
            }

        elif system_repo != None and self.__CheckSupportedSystem(system_repo) and pkg_name != None and pkg_version != None:
            params = {
                "versionKey.system": system_repo,
                "versionKey.name": pkg_name,
                "versionKey.version": pkg_version
            }
        else:
            params = {}

        if len(params) != 0:
            try:
                r = requests.get(url, params=params)
            except:
                return {"error": f"Connection with {url} status invalid"}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable probably status 404", "response": r.content.decode('utf-8')}
        else:
            return {"error": "Incomplete parameters"}
        
        return r_json

# Fuctions Asyncs
    @cache
    async def async_GetPackage(self, system_repo, pkg_name):
        """Async method with HTTPX
        GetPackage returns information about a package, including a list of its
        available versions, with the default version marked if known.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}"}
                
                try:
                    r_json = r.json()
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    async def async_GetVersion(self, system_repo, pkg_name, pkg_version):
        """Async method with HTTPX
        GetVersion returns information about a specific package version, including
        its licenses and any security advisories known to affect it.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}"}

                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    async def async_GetRequirements(self, system_repo, pkg_name, pkg_version):
        """Async method with HTTPX
        GetRequirements returns the requirements for a given version in a
        system-specific format. Requirements are currently only available for
        NuGet.

        Requirements are the dependency constraints specified by the version.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems' 
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements"}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    async def async_GetDependencies(self, system_repo, pkg_name, pkg_version):
        """Async method with HTTPX
        GetDependencies returns a resolved dependency graph for the given package
        version. Dependencies are currently available for Go, npm, Cargo, Maven
        and PyPI.

        Dependencies are the resolution of the requirements (dependency
        constraints) specified by a version.

        The dependency graph should be similar to one produced by installing the
        package version on a generic 64-bit Linux system, with no other
        dependencies present. The precise meaning of this varies from system to
        system.
        """
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies"}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    async def async_GetProject(self, repo): # ex github.com/owner/pkg
        """Async method with HTTPX
        GetProject returns information about projects hosted by GitHub, GitLab, or
        BitBucket, when known to us.
        """
        if self.__CheckSupportedRepo(repo):
            repo = urllib.parse.quote_plus(repo)
            
            url = f'https://api.deps.dev/v3alpha/projects'
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{repo}', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{repo} status invalid"}
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    @cache
    async def async_GetAdvisory(self, advisor_id): # ex GHSA-xxxx-xxxx-xxxx
        """Async method with HTTPX
        GetAdvisory returns information about security advisories hosted by OSV.
        """
        if advisor_id.split('-', 1)[0] == "GHSA":

            url = f'https://api.deps.dev/v3alpha/advisories'

            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{advisor_id}', timeout=60)
                except:
                    return {"error": f"Connection with {url}/{advisor_id} status invalid"}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404"}
                return r_json
        else:
            return {"error": "Advisor ID no supported", "example": "GHSA-xxxx-xxxx-xxxx"}
    @cache
    async def async_Search(self, system_repo=None, pkg_name=None, pkg_version=None, hash_type=None, hash_value=None): # ex GHSA-xxxx-xxxx-xxxx
        """Query returns information about multiple package versions, which can be
        specified by name, content hash, or both.

        It is typical for hash queries to return many results; hashes are matched
        against multiple release artifacts (such as JAR files) that comprise
        package versions, and any given artifact may appear in many package
        versions.
        """
        url = f'https://api.deps.dev/v3alpha'

        if hash_type != None and hash_value != None and self.__CheckSupportedHashs(hash_type):
            hash_value = urllib.parse.quote_plus(hash_value)
            params = {
                "hash.type": hash_type,
                "hash.value": hash_value
            }

        elif system_repo != None and self.__CheckSupportedSystem(system_repo) and pkg_name != None and pkg_version != None:
            params = {
                "versionKey.system": system_repo,
                "versionKey.name": pkg_name,
                "versionKey.version": pkg_version
            }
        else:
            params = {}

        if len(params) != 0:
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get('/query', params=params, timeout=60)
                except:
                    return {"error": f"Connection with {url} status invalid"}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable probably status 404", "response": r.content.decode('utf-8')}
        else:
            return {"error": "Incomplete parameters"}
        
        return r_json