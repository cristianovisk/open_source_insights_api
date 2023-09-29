import argparse
import json
import time
from open_source_insights_api.os_insights import query
from functools import cache
from rich.live import Live
from rich.table import Table
import threading
from packageurl import PackageURL

def args():
    parser = argparse.ArgumentParser(description="SBOM Insights")
    parser.add_argument("-f", "--file", type=str, const=True, nargs='?', default='sbom.json', help="Define sbom.json to consume e return insights. (Default is sbom.json)")
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
        table.add_column("Package")
        table.add_column("Repository")
        table.add_column("Version")
        table.add_column("Latest Version")
        table.add_column("Dep Direct")
        table.add_column("Dep Indirect")

        for pkg in self.all_pkgs_info:
            table.add_row(
                f"{pkg.get('pkg_name')}", 
                f"{pkg.get('system')}", 
                f"{pkg.get('recv_version')}",
                f"{pkg.get('latest')}",
                f"{pkg.get('dep_dir')}",
                f"{pkg.get('dep_indir')}"
            )
        return table
    

    def __get_latest_version(self, pkg_info_os):
        for version in pkg_info_os.get('versions'):
            if version.get('isDefault'):
                return version.get('versionKey').get('version')
              
    def __get_relations_deps(self, pkg_deps_os):
        c_relations = {'direct': 0, 'indirect': 0}
        for node in pkg_deps_os.get('nodes'):
            if node.get('relation') == 'DIRECT':
                c_relations['direct'] += 1
            if node.get('relation') == 'INDIRECT':
                c_relations['indirect'] += 1
        return c_relations
    
    def __get_relation_indirect(self, pkg_deps_os):
        return self.__get_relations_deps(pkg_deps_os).get('indirect')

    def __get_relation_direct(self, pkg_deps_os):
        return self.__get_relations_deps(pkg_deps_os).get('direct')


    def process(self):
        for comp in self.sbom.get('components'):
            if comp.get('purl'):
                model = {
                    "pkg_name": None,
                    "system": None,
                    "recv_version": None,
                    "latest": None,
                    "dep_dir": None,
                    "dep_indir": None
                }
                purl = PackageURL.from_string(comp.get('purl'))
                if purl.namespace:
                    pkg_name = f'{purl.namespace}/{purl.name}'
                else:
                    pkg_name = f'{purl.name}'
                pkg_info = self.osi.GetPackage(purl.type, pkg_name)
                pkg_deps = self.osi.GetDependencies(purl.type, pkg_name, purl.version)
                model['pkg_name'] = pkg_name
                model['system'] = purl.type
                model['recv_version'] = purl.version
                model['latest'] = self.__get_latest_version(pkg_info)
                model['dep_dir'] = self.__get_relation_direct(pkg_deps)
                model['dep_indir'] = self.__get_relation_indirect(pkg_deps)

                self.all_pkgs_info.append(model)

def cli():
    ARGS = args()
    if ARGS.file:
        file_path = ARGS.file
        with open(file_path, 'r') as file:
            sbom = json.loads(file.read())

        sbom_process = Sbom_Process_CLI(sbom_json=sbom)
        threading.Thread(target=sbom_process.process).start()
        with Live(sbom_process.generate_table(), refresh_per_second=4) as live:
            while True:
                time.sleep(0.4)
                live.update(sbom_process.generate_table())
                if threading.active_count() == 2:
                    break
        exit(0)
    else:
        print('Please --help')

if __name__ == "__main__":
    cli()