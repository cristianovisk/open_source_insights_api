import requests
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