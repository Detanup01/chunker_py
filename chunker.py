import os
import steam.monkey
steam.monkey.patch_minimal()
from steam.enums import EResult
from steam.client import SteamClient, EMsg, _cli_input, getpass
from steam.client.cdn import CDNClient, CDNDepotManifest, CDNDepotFile
import argparse
cwd = os.getcwd()
# Parser for to CLI thing
parser = argparse.ArgumentParser(description="Chunk dowloader",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("username",nargs='?', help="Steam Username")
parser.add_argument("password",nargs='?', help="Steam Password")
parser.add_argument("app",nargs='?', type=int, help="App Id")
parser.add_argument("depot", nargs='?', type=int, help="Depot Id")
parser.add_argument("manifest", nargs='?', type=int, help="Manifest Id")
parser.add_argument("path", nargs='?', default=cwd, help="Destination location")
args = parser.parse_args()
#print(vars(args))

# to save manifest and check if anon user
def savemanifest(data,name):
    f = open(name, "wb")
    f.write(data)
    f.close()

def is_anon():
    return os.path.isfile("anon.txt")

def savechunk(data,path):
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path),exist_ok=True)
    f = open(path, "wb")
    f.write(data)
    f.close()

# From steamctl but with little edit
class BasedDepotFile(CDNDepotFile):

    def get_maps(self):
        return self.file_mapping

class BasedDepotManifest(CDNDepotManifest):
    DepotFileClass = BasedDepotFile
    
    # maybe decrypt here if we have a key?

class BasedCDNClient(CDNClient):
    DepotManifestClass = BasedDepotManifest

    def __init__(self, *args, **kwargs):
        CDNClient.__init__(self, *args, **kwargs)

    def get_manifest(self, app_id, depot_id, manifest_gid, decrypt=True, manifest_request_code=None):
        print(str(app_id) + " " + str(depot_id) + " " + str(manifest_gid))
        if not os.path.isfile("{}_{}.manifest".format(depot_id,manifest_gid)):
            if manifest_request_code is None:
                manifest_request_code = CDNClient.get_manifest_request_code(self, app_id, depot_id, manifest_gid)
                print(manifest_request_code)
            manifest = CDNClient.get_manifest(self, app_id, depot_id, manifest_gid, decrypt, manifest_request_code)
            serialized = manifest.serialize(True)
            savemanifest(serialized,"{}_{}.manifest".format(depot_id,manifest_gid))
        else:
            print("manifest already exist, we dont do much here!")
    
    def get_based(self, app_id, depot_id, manifest_gid):
        fp = open("{}_{}.manifest".format(depot_id,manifest_gid),"rb")
        manifest = self.DepotManifestClass(self, app_id, fp.read())
        fp.close()
        return manifest

class BasedSteamClient(SteamClient):
    def __init__(self, *args, **kwargs):
        SteamClient.__init__(self, *args, **kwargs)

    def anon_login(self):
        return self.anonymous_login()
    
    def send_login(self,username,password):
        return self.cli_login(username, password)

    def get_cdnclient(self):
        return BasedCDNClient(self)

basedClient = BasedSteamClient()

if is_anon():
    basedClient.anon_login()
else:
    if args.username is None:
        name = _cli_input("Enter your name: ")
    else:
        name = args.username
    if args.password is None:
        password = getpass()
    else:
        password = args.password
    result = basedClient.send_login(name,password)
    print(EResult(result))
print()
basedCDN = basedClient.get_cdnclient()
if args.app is None:
    appid = int(_cli_input("Enter AppId: "))
else:
    appid = args.app
if args.depot is None:
    depot_id = int(_cli_input("Enter DepotId: "))
else:
    depot_id = args.depot
if args.manifest is None:
    manifest_gid = int(_cli_input("Enter Manifest Id: "))
else:
    manifest_gid = args.manifest

manifest = basedCDN.get_manifest(appid, depot_id, manifest_gid)
basedM = basedCDN.get_based(appid, depot_id, manifest_gid)
for mfile in basedM:
    maps = mfile.get_maps()
    print(maps.filename)
    for chunk in maps.chunks:
        shahex = chunk.sha.hex()
        if not os.path.isfile(args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex)):
            resp = CDNClient.cdn_cmd(basedCDN,'depot', '%s/chunk/%s' % (depot_id, shahex))
            savechunk(resp.content, args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex))