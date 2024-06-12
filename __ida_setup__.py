# -*- coding: utf-8 -*-
from os.path import join
from sys import platform
from distutils import log
from os import environ, makedirs

from setuptools.dist import Distribution
from setuptools.command.install import install


class IdaPluginInstallCommand(install):
    description = "Install the current plugin in IDA plugin folder."

    def install_dependencies(self, dist: Distribution, install_dir: str) -> None:
        """ Recursively install dependency using pip (for those on pipy) """
        if not len(dist.install_requires):
            return

        # Inner import in order to prevent build breakage
        import pip

        for dependency in dist.install_requires:
            self.announce(f"[IDA PLUGIN INSTALL] installing dependency: {dependency} -> {install_dir}",
                          level=log.INFO)

            if not self.dry_run:
                pip.main(["install", "-t", install_dir, "--ignore-installed", dependency,])

    def install_packages(self, dist: Distribution, install_dir: str) -> None:
        """ Install python packages """
        for package in dist.packages:
            self.announce(f"[IDA PLUGIN INSTALL] copy package: {package} -> {install_dir}",
                          level=log.INFO)

            if not self.dry_run:
                self.copy_tree(package, join(install_dir, package))

    def install_plugins(self, dist: Distribution, install_dir: str) -> None:
        """ Install ida plugins entry points """
        ida_plugins = dist.package_data.get("ida_plugins", [])

        for plugin in ida_plugins:
            self.announce(f"[IDA PLUGIN INSTALL] copy plugin: {plugin} -> {install_dir}",
                          level=log.INFO)

            if not self.dry_run:
                self.copy_file(plugin, install_dir)

    def run(self, *args, **kwargs) -> None:
        """ Install ida plugins routine """
        dist: Distribution = self.distribution

        install_dir: str = self.root  # respect user-override install dir

        if not install_dir:  # otherwise return the IDA install dir
            install_dir = IdaPluginInstallCommand._get_install_dir()

        self.install_dependencies(dist, install_dir)

        self.install_packages(dist, install_dir)
        self.install_plugins(dist, install_dir)

        install.run(self)

    @staticmethod
    def _get_install_dir() -> str:
        if platform.startswith("win") or platform == "cygwin":              # Windows
            install_dir = join(environ["APPDATA"], "Hex-Rays", "IDA Pro", "plugins")
        elif any(platform.startswith(p) for p in ("linux", "darwin",)):     # Linux or MacOS
            install_dir = join(environ["HOME"], ".idapro", "plugins")
        else:
            raise EnvironmentError(f"Unsupported platform {platform}")

        makedirs(install_dir, mode=0o755, exist_ok=True)

        return install_dir
