
import sys
import os
import os.path
import pathlib
import re
import urllib.request
import urllib.parse
import shutil
import gzip
import tempfile

import logging

SIMPILE = "^(?P<key>[\w-]+): (?P<value>.+)\n"
COMPOUNDKEY = "^(?P<key>.+):\n"
COMPOUNDVALUE = " (?P<value>.+)\n"

logging.basicConfig(filename="Parser.log")

class PackageList():
    PATTERN = "(?P<name>[\w-]+) (?P<package>\w+) (?P<section>[\w/\-]+) (?P<priority>\w+)([ arch=]{0,6})(?(5)(?P<arch>[\w,]+))"
    ARCH = "(?<=arch=)\w+"
    def __init__(self):
        self.lists = []

    def feed(self, content):
        matches = re.search(self.PATTERN, content)
        self.lists.append(matches.groupdict())

class PackageFiles():
    PATTERN = "(?P<md5>[a-z0-9]+) (?P<size>\d+) (?P<name>[\w_-]+)"
    def __init__(self):
        self.lists = []

    def feed(self, content):
        matches = re.search(self.PATTERN, content)
        self.lists.append(matches.groupdict())

class PackageChecksumSha1:
    PATTERN = "(?P<sha1>[\w]+) (?P<size>\d+) (?P<name>[\w_-]+)"
    def __init__(self):
        self.lists = []

    def feed(self, content):
        matches = re.search(self.PATTERN, content)
        self.lists.append(matches.groupdict())

class PackageChecksumSha256:
    PATTERN = "(?P<sha256>[\w]+) (?P<size>\d+) (?P<name>[\w_-]+)"
    def __init__(self):
        self.lists = []

    def feed(self, content):
        matches = re.search(self.PATTERN, content)
        self.lists.append(matches.groupdict())

class PackageBinary:
    PATTERN = ", "
    def __init__(self):
        self.lists = []
    
    def feed(self, content):
        matches = re.split(self.PATTERN, content)
        self.lists.append(matches)

class PackageDepends:
    SEP1 = ", "
    SEP2 = " \| "
    PATTERN = "(?P<name>[\w\.-]+)\s*\({0,1}(?P<version>[^\[\])]*)\){0,1}\s*\[{0,1}(?P<arch>[^\[\])]*)\]{0,1}"
    def __init__(self, content):
        self.lists = []
        self.feed(content)

    def feed(self, content):
        items = re.split(self.SEP1, content)
        
        for item in items:
            pieces = []
            options = re.split(self.SEP2, item)
            for opt in options:
                matches = re.search(self.PATTERN, opt)
                pieces.append(matches.groupdict())
            self.lists.append(pieces) 

class PackageMultiline:
    def __init__(self, content):
        self.lists = []
        self.feed(content)
    
    def feed(self, content):
        self.lists.append(content.strip())

class PackageInfo():
    def __init__(self, content):
        self.maps = {}
        for info in content:
            for pattern in [SIMPILE, COMPOUNDKEY, COMPOUNDVALUE]:
                matches = re.match(pattern, info)
                if matches:
                    break
            if not matches:
                assert(0) 
            try:
                row = matches['key']
                if row == "Files":                          
                    self.__setitem__(row, PackageFiles())
                elif row == "Package-List":        
                    self.__setitem__(row, PackageList())
                elif row == "Checksums-Sha1":
                    self.__setitem__(row, PackageChecksumSha1())

                elif row == "Checksums-Sha256":
                    self.__setitem__(row, PackageChecksumSha256())
                elif row == "Binary":
                    self.__setitem__(row, PackageBinary())
                elif row == "Build-Depends":
                    self.__setitem__(row, PackageDepends(matches['value']))
                elif row == "Package" or row == "Filename":
                    self.__setitem__(row, matches['value'])
                else:
                    self.__setitem__(row, PackageMultiline(matches['value']))
                self.doing = row
            except IndexError as index:                
                self.__getitem__(self.doing).feed(matches['value'])

        self.__delattr__('doing')

    def __setitem__(self, key, value):
        self.maps[key] = value

    def __getitem__(self, key):
        return self.maps[key]
        
class PackageParser():
    def __init__(self):
        self.result = {}

    def feed(self, content):
        p = PackageInfo(content)
        self.result[p['Package']] = p

    def get_result(self):
        return self.result

class RecipeGenerator():
    def __init__(self, apt_source, destdir):
        self.apt_source = os.path.abspath(apt_source)
        self.destdir = os.path.abspath(destdir)
        self.parser = PackageParser()
        self.packages = []
        self.prepared = False
        with open(self.apt_source, 'r') as sources:
            slices = []
            for line in sources:
                if line == "\n":
                    self.packages.append(slices)
                    slices = []
                else:
                    slices.append(line)
        for p in self.packages:
            self.parser.feed(p)

        self.package_maps = self.parser.get_result()
    
    def __getitem__(self, key):
        return self.package_maps[key]

    def keys(self):
        return self.package_maps.keys()

    def prepare(self):
        if not self.prepared:
            self.rootpath = os.path.join(self.destdir, "meta-qti-ubuntu")
            if not os.path.exists(self.rootpath):
                os.mkdir(self.rootpath)
            self.prepared = True
        
    def generate_bbfile(self, rootpath, metadata, ext=".bb"):
        #rootpath / recipes-Section / package_name / package_name.bb
        recipe_name = metadata['Package'] + "_" + metadata['Standards-Version'] + ext
        recipe_dir = metadata['Package']
        recipe_section = "recipes-%s" % metadata['Section']
        
        try:
            bb_dir = pathlib.Path(rootpath) / recipe_section / recipe_dir
            bb_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

            bb_path = bb_dir.joinpath(recipe_name)
            bb_path.touch(mode='w+')
        except FileExistsError as e:
            logging.warn(e)
        
        return bb_path

    def translate_metadata(self, metadata, fd):
        MIRROR_SITE = "ports.ubuntu.com" 
        lines = []
        lines.append('SECTION = ' + '"' + metadata['Section'] + '"')
        lines.append('PV = ' + '"' + metadata['Version'] + '"')
        lines.append('HOMEPAGE = ' + '"' + metadata['Homepage'] + '"')
        
        #translate DEPENDS
        line = 'DEPENDS = "'
        for dep in metadata['Build-Depends'].lists:
            line += ' '
            line += dep[0]['name'] 
        line += '"'
        lines.append(line)
        pass
        

    def build_recipe(self, name):
        self.prepare()
        recipe_metadata = self.package_maps[name]
        bb_path = self.generate_bbfile(self.rootpath, recipe_metadata)        
        
        with bb_path.open(mode="w") as recipe:
            self.translate_metadata(recipe_metadata, recipe)
            
class AptPackageDownloader():
    MIRROR_SITE = 'https://repo.huaweicloud.com/ubuntu-ports/'
    POOLS = ['main', 'universe', 'multiverse', 'restricted']
    DIST = 'bionic'
    ARCH = 'binary-arm64'
    def __init__(self):
        self.Packages = []
        self.recipes = []
        self.prepare()
        for pkg in self.Packages:
            #parse Packages from MIRROR_SITE
            self.recipes.append(RecipeGenerator(pkg, ''))

    def prepare(self):
        for pool in self.POOLS:
            #get Packages.gz from MIRROR_SITE
            packages_gz = self.MIRROR_SITE + str(pathlib.Path('dists') / self.DIST / pool / self.ARCH / 'Packages.gz')
            pathlib.Path(pool).mkdir(exist_ok=True)
            local_packages_gz = pathlib.Path(pool)/'Packages.gz'
            local_packages = pathlib.Path(pool)/'Packages'
            with urllib.request.urlopen(packages_gz) as response:
                #TODO only write file when updates
                with local_packages_gz.open('wb') as gz_file:
                    shutil.copyfileobj(response, gz_file)
            with gzip.open(local_packages_gz) as gz:
                with local_packages.open('wb') as package:
                    package.write(gz.read())
            self.Packages.append(local_packages)

    def download_debs(self, deb_list, dest):
        for deb_name in deb_list:
            for generator in self.recipes:
                if deb_name in generator.keys():
                    deb_file = self.download_one(generator[deb_name])
                    if not pathlib.Path(dest).exists():
                        pathlib.Path(dest).mkdir()
                    #move the debian package to dest dir
                    shutil.move(deb_file, dest)
                    break

    def download_one(self, package_info):
        filename = package_info['Filename']
        #obtain full url for the debian package
        urlpath = self.MIRROR_SITE + filename
        print("To download %s" % filename)
        with urllib.request.urlopen(urlpath) as response:
            with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                shutil.copyfileobj(response, tmpfile)
                tmpfile_name = pathlib.Path(tmpfile.name)
                newname = tmpfile_name.parent / pathlib.Path(filename).name
                #rename tempfile with debian package name
                tmpfile_name.rename(newname)
                return str(newname)
            

if __name__ == "__main__":
    DEBS = ['libcdio-dev']
    downloader = AptPackageDownloader()
    downloader.download_debs(DEBS, 'tmp')
