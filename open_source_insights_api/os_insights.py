from asyncio import run, gather, sleep
import httpx as requests
from httpx import AsyncClient
import json
import urllib.parse

class query:
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
    def GetPackage(self, system_repo, pkg_name):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}", "status_code": r.status_code}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    
    def GetVersion(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}", "status_code": r.status_code}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
        
    def GetRequirements(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}", "status_code": r.status_code}

            if r.status_code == 404:
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
        
    def GetDependencies(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies'
            
            try:
                r = requests.get(url)
            except:
                return {"error": f"Connection with {url}", "status_code": r.status_code}

            if r.status_code == 404:
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    
    def GetProject(self, repo): # ex github.com/owner/pkg
        if self.__CheckSupportedRepo(repo):
            repo = urllib.parse.quote_plus(repo)
            
            url = f'https://api.deps.dev/v3alpha/projects/{repo}'

            try:
                r = requests.get(url)
            except:
                return ConnectionError
            if r.status_code == 404:
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}

    def GetAdvisory(self, advisor_id): # ex GHSA-xxxx-xxxx-xxxx
        if advisor_id.split('-', 1)[0] == "GHSA":
            
            url = f'https://api.deps.dev/v3alpha/advisories/{advisor_id}'

            try:
                r = requests.get(url)
            except:
                return ConnectionError
            
            if r.status_code == 404:
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable"}
            
            return r_json
        else:
            return {"error": "Advisor ID no supported", "example": "GHSA-xxxx-xxxx-xxxx"}
        
    def Search(self, system_repo=None, pkg_name=None, pkg_version=None, hash_type=None, hash_value=None): # ex GHSA-xxxx-xxxx-xxxx
        
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
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            
            if r.status_code == 404:
                return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
            
            try:
                r_json = json.loads(r.content)
            except:
                return {"error": "JSON returned from API is not serializable", "response": r.content.decode('utf-8')}
        else:
            return {"error": "Incomplete parameters"}
        
        return r_json

# Fuctions Asyncs
    async def async_GetPackage(self, system_repo, pkg_name):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}", "status_code": r.status_code}
                
                if r.status_code == 404:    
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name} status invalid", "status_code": r.status_code}
                
                try:
                    r_json = r.json()
                except:
                    return {"error": "JSON returned from API is not serializable"}
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    
    async def async_GetVersion(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}", "status_code": r.status_code}
                
                if r.status_code == 404:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version} status invalid", "status_code": r.status_code}

                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
        
    async def async_GetRequirements(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems' 
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements", "status_code": r.status_code}

                if r.status_code == 404:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:requirements status invalid", "status_code": r.status_code}
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
        
    async def async_GetDependencies(self, system_repo, pkg_name, pkg_version):
        if self.__CheckSupportedSystem(system_repo):
            pkg_name = urllib.parse.quote_plus(pkg_name)
            url = f'https://api.deps.dev/v3alpha/systems'
            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies", "status_code": r.status_code}

                if r.status_code == 404:
                    return {"error": f"Connection with {url}/{system_repo}/packages/{pkg_name}/versions/{pkg_version}:dependencies status invalid", "status_code": r.status_code}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}
    
    async def async_GetProject(self, repo): # ex github.com/owner/pkg
        if self.__CheckSupportedRepo(repo):
            repo = urllib.parse.quote_plus(repo)
            
            url = f'https://api.deps.dev/v3alpha/projects'
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{repo}', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{repo} status invalid", "status_code": r.status_code}
                
                if r.status_code == 404:
                    return {"error": f"Connection with {url}/{repo} status invalid", "status_code": r.status_code}
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable"}
                
                return r_json
        else:
            return {"error": "System repository not supported", "supported": self.systems}

    async def async_GetAdvisory(self, advisor_id): # ex GHSA-xxxx-xxxx-xxxx
        if advisor_id.split('-', 1)[0] == "GHSA":

            url = f'https://api.deps.dev/v3alpha/advisories'

            
            async with AsyncClient(base_url=url) as client:
                try:
                    r = await client.get(f'/{advisor_id}', timeout=10)
                except:
                    return {"error": f"Connection with {url}/{advisor_id} status invalid", "status_code": r.status_code}
                
                if r.status_code == 404:
                    return {"error": f"Connection with {url}/{advisor_id} status invalid", "status_code": r.status_code}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable"}
                return r_json
        else:
            return {"error": "Advisor ID no supported", "example": "GHSA-xxxx-xxxx-xxxx"}
        
    async def async_Search(self, system_repo=None, pkg_name=None, pkg_version=None, hash_type=None, hash_value=None): # ex GHSA-xxxx-xxxx-xxxx
        
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
                    r = await client.get('/query', params=params, timeout=10)
                except:
                    return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
                
                if r.status_code == 404:
                    return {"error": f"Connection with {url} status invalid", "status_code": r.status_code}
                
                try:
                    r_json = json.loads(r.content)
                except:
                    return {"error": "JSON returned from API is not serializable", "response": r.content.decode('utf-8')}
        else:
            return {"error": "Incomplete parameters"}
        
        return r_json