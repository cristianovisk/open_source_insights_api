import argparse
import json
import time
from os_insights import query
from rich.table import Table
from rich.progress import Progress
from rich.console import Console
try:
    from open_source_insights_api import __version__
except:
    from __init__ import __version__
import pandas as pd
import re
import threading
from packageurl import PackageURL

def args():
    parser = argparse.ArgumentParser(description="SBOM Insights")
    parser.add_argument("-f", "--file", type=str, const=True, nargs='?', default='sbom.json', help="Define sbom.json to consume e return insights. (Default is sbom.json)")
    parser.add_argument("-o", "--output", type=str, const=True, nargs='?', default='output.json', help="Output JSON to file, NEED --json to works! (Default is output.json)")
    parser.add_argument("-j", "--json", action="store_true", help="Print output as JSON instead of a table.")
    parser.add_argument("-v", "--version", action="store_true", help="Show version.")
    arguments = parser.parse_args()
    return arguments


class Sbom_Process_CLI:
    def __init__(self, sbom_json) -> None:
        self.sbom = sbom_json
        self.osi = query()
        self.all_pkgs_info = []

    def generate_table(self) -> Table:
        """Make a new table."""
        table = Table(title="SBOM Insights")
        table.add_column(":package: Package")
        table.add_column(":package: Repository")
        table.add_column(":right_arrow: Version")
        table.add_column(":up_arrow: Latest")
        table.add_column(":gear: Dep Direct")
        table.add_column(":gear: Dep Indirect")
        table.add_column(":skull: Vulnerabilities")
        table.add_column(":light_bulb: OpenSSF Score")
        table.add_column(":hammer_and_wrench: Maintainability")
        table.add_column(":credit_card: License")
       
        for pkg in self.all_pkgs_info:
            dep_dir = f"{pkg.get('dep_indir')}"
            dep_indir = f"{pkg.get('dep_dir')}"
            maintained = ""
            license = f"{pkg.get('license')}"
            if pkg.get('recv_version') != pkg.get('latest'): 
                latest = f":new: {pkg.get('latest')}"
            else:
                latest = f"{pkg.get('latest')}"
            if pkg.get('vulnerabilities') != 0:
                vulnerabilities = f":red_circle: {pkg.get('vulnerabilities')}"
            else:
                vulnerabilities = f":green_circle: {pkg.get('vulnerabilities')}"

            if pkg.get('maintained') != None:
                if int(pkg.get('maintained')) == 0:
                    maintained = f":red_circle: {pkg.get('maintained')}"
                elif int(pkg.get('maintained')) < 5:
                    maintained = f":yellow_circle: {pkg.get('maintained')}"
                elif int(pkg.get('maintained')) < 10:
                    maintained = f":blue_circle: {pkg.get('maintained')}"
                elif int(pkg.get('maintained')) == 10:
                    maintained = f":green_circle: {pkg.get('maintained')}"
            
            if pkg.get('dep_dir') <= 30:
                dep_dir = f":green_circle: {pkg.get('dep_dir')}"
            elif pkg.get('dep_dir') < 60:
                dep_dir = f":blue_circle: {pkg.get('dep_dir')}"
            elif pkg.get('dep_dir') <= 100:
                dep_dir = f":yellow_circle: {pkg.get('dep_dir')}"
            elif pkg.get('dep_dir') > 100:
                dep_dir = f":red_circle: {pkg.get('dep_dir')}"

            if pkg.get('dep_indir') <= 30:
                dep_indir = f":green_circle: {pkg.get('dep_indir')}"
            elif pkg.get('dep_indir') < 60:
                dep_indir = f":blue_circle: {pkg.get('dep_indir')}"
            elif pkg.get('dep_indir') <= 100:
                dep_indir = f":yellow_circle: {pkg.get('dep_indir')}"
            elif pkg.get('dep_indir') > 100:
                dep_indir = f":red_circle: {pkg.get('dep_indir')}"

            table.add_row(
                f"{pkg.get('pkg_name')}", 
                f"{pkg.get('system')}".upper(), 
                f"{pkg.get('recv_version')}",
                f"{latest}",
                f"{dep_dir}",
                f"{dep_indir}",
                f"{vulnerabilities}",
                f"{pkg.get('openssf_score')}",
                f"{maintained}",
                f"{license}"
            )
        pd.DataFrame(self.all_pkgs_info).to_excel('output.xlsx', sheet_name="SBOM_INSIGHTS", index=False, header=True)
        return table
    
    def __get_osscore(self, pkg_version_info):
        repo_url = ""
        score = None
        regex_github = '(github.com\/[a-zA-Z0-9\-\_]{2,}\/[a-zA-Z0-9\-\_]{2,})'
        if pkg_version_info.get('links'):
            if len(pkg_version_info.get('links')) == 0:
                return ""
            else:
                for link in pkg_version_info.get('links'):
                    if link.get('label') == 'SOURCE_REPO':
                        try:
                            repo_url = re.search(regex_github, link.get('url'))[0]
                        except:
                            repo_url = ""
        if repo_url != "":
            project_data = self.osi.GetProject(repo_url)
            if project_data.get('scorecard'):
                score = project_data.get('scorecard').get('overallScore')

        return score
    
    def __get_score_maintained(self, pkg_version_info):
        repo_url = ""
        score = None
        regex_github = '(github.com\/[a-zA-Z0-9\-\_]{2,}\/[a-zA-Z0-9\-\_]{2,})'
        if pkg_version_info.get('links'):
            if len(pkg_version_info.get('links')) == 0:
                return ""
            else:
                for link in pkg_version_info.get('links'):
                    if link.get('label') == 'SOURCE_REPO':
                        try:
                            repo_url = re.search(regex_github, link.get('url'))[0]
                        except:
                            repo_url = ""
        if repo_url != "":
            project_data = self.osi.GetProject(repo_url)
            if project_data.get('scorecard'):
                for check in project_data.get('scorecard').get('checks'):
                    if check.get('name') == "Maintained":
                        score = float(check.get('score'))

        return score
            

    def __get_latest_version(self, pkg_info_os):
        if pkg_info_os.get('versions'):
            for version in pkg_info_os.get('versions'):
                if version.get('isDefault'):
                    return version.get('versionKey').get('version')
    
    def __get_latest_version_date(self, pkg_info_os):
        if pkg_info_os.get('versions'):
            for version in pkg_info_os.get('versions'):
                if version.get('isDefault'):
                    return version.get('publishedAt')
              
    def __get_relations_deps(self, pkg_deps_os):
        c_relations = {'direct': 0, 'indirect': 0}
        if pkg_deps_os.get('nodes'):
            for node in pkg_deps_os.get('nodes'):
                if node.get('relation') == 'DIRECT':
                    c_relations['direct'] += 1
                if node.get('relation') == 'INDIRECT':
                    c_relations['indirect'] += 1
            return c_relations
    
    def __get_relation_indirect(self, pkg_deps_os):
        relations = self.__get_relations_deps(pkg_deps_os)
        if relations:
            return relations.get('indirect')
        else:
            return 0

    def __get_relation_direct(self, pkg_deps_os):
        relations = self.__get_relations_deps(pkg_deps_os)
        if relations:
            return relations.get('direct')
        else:
            return 0

    def __get_license(self, pkg_version_info):
        if pkg_version_info.get('licenses') != None and len(pkg_version_info.get('licenses')) > 0:
            return pkg_version_info.get('licenses')[0]
        else:
            repo_url = ""
            score = None
            regex_github = '(github.com\/[a-zA-Z0-9\-\_]{2,}\/[a-zA-Z0-9\-\_]{2,})'
            if pkg_version_info.get('links'):
                if len(pkg_version_info.get('links')) == 0:
                    return ""
                else:
                    for link in pkg_version_info.get('links'):
                        if link.get('label') == 'SOURCE_REPO':
                            try:
                                repo_url = re.search(regex_github, link.get('url'))[0]
                            except:
                                repo_url = ""
            if repo_url != "":
                project_data = self.osi.GetProject(repo_url)
                if project_data.get('license'):
                    return project_data.get('license')
        
    def __get_vulnerabilities(self, pkg_version_info):
        if pkg_version_info.get('advisoryKeys'):
            return len(pkg_version_info.get('advisoryKeys'))
        else:
            return 0

    def process(self):
        with Progress() as progress:
            task = progress.add_task("[green bold]Processing...", total=len(self.sbom.get('components')))
            # while not progress.finished:
            for comp in self.sbom.get('components'):
                if comp.get('purl'):
                    model = {
                        "pkg_name": None,
                        "system": None,
                        "recv_version": None,
                        "latest": None,
                        "publishedAt": None,
                        "dep_dir": None,
                        "dep_indir": None,
                        "vulnerabilities": None,
                        "openssf_score": None,
                        "maintained": None,
                        "license": None
                    }
                    purl = PackageURL.from_string(comp.get('purl'))
                    if purl.namespace:
                        pkg_name = f'{purl.namespace}/{purl.name}'
                    else:
                        pkg_name = f'{purl.name}'
                    pkg_info = self.osi.GetPackage(purl.type, pkg_name)
                    pkg_version = self.osi.GetVersion(purl.type, pkg_name, purl.version)
                    pkg_deps = self.osi.GetDependencies(purl.type, pkg_name, purl.version)
                    model['pkg_name'] = pkg_name
                    model['system'] = purl.type
                    model['recv_version'] = purl.version
                    model['latest'] = self.__get_latest_version(pkg_info)
                    model['publishedAt'] = self.__get_latest_version_date(pkg_info)
                    model['dep_dir'] = self.__get_relation_direct(pkg_deps)
                    model['dep_indir'] = self.__get_relation_indirect(pkg_deps)
                    model['vulnerabilities'] = self.__get_vulnerabilities(pkg_version)
                    model['openssf_score'] = self.__get_osscore(pkg_version)
                    model['maintained'] = self.__get_score_maintained(pkg_version)
                    model['license'] = self.__get_license(pkg_version)

                    progress.update(task, advance=1, description=f"[green bold]Processing: [bold blue]{purl.to_string()}")
                    self.all_pkgs_info.append(model)
def cli():
    ARGS = args()
    console = Console()
    if ARGS.version:
        console.print(f'Current version: {__version__}')
        exit(0)
        
    if ARGS.file:
        file_path = ARGS.file
        with open(file_path, 'r') as file:
            sbom = json.loads(file.read())

        sbom_process = Sbom_Process_CLI(sbom_json=sbom)
        sbom_process.process()

        if ARGS.json:
            console.print(json.dumps(sbom_process.all_pkgs_info, indent=4))
            with open(ARGS.output, 'w') as file:
                file.write(json.dumps(sbom_process.all_pkgs_info, indent=4))
        else:
            console.print(sbom_process.generate_table())
    else:
        print('Please --help')

if __name__ == "__main__":
    cli()