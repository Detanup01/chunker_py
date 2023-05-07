import os
import steam.monkey
steam.monkey.patch_minimal()
from steam.enums import EResult
from steam.core.manifest import DepotManifest, DepotFile
from steam.client import SteamClient, EMsg, _cli_input, getpass
from steam.client.cdn import CDNClient, CDNDepotManifest, CDNDepotFile
from steam.core.crypto import symmetric_decrypt, symmetric_encrypt
import argparse
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED, BadZipFile
from struct import pack
import lzma

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
    f.truncate()
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
class BasedDepotFile(DepotFile):

    def __init__(self, manifest, file_mapping):
        DepotFile.__init__(self, manifest, file_mapping)

    def get_maps(self):
        return self.file_mapping

class BasedDepotManifest(DepotManifest):
    DepotFileClass = BasedDepotFile

    def __init__(self, app_id, data):
        self.app_id = app_id
        DepotManifest.__init__(self, data)

    def deserialize(self, data):
        DepotManifest.deserialize(self, data)
    
    def serialize(self, compress=True):
        """Serialize manifest

        :param compress: wether the output should be Zip compressed
        :type  compress: bytes
        """
        data = BytesIO()

        part = self.payload.SerializeToString()
        data.write(pack('<II', DepotManifest.PROTOBUF_PAYLOAD_MAGIC, len(part)))
        data.write(part)

        part = self.metadata.SerializeToString()
        data.write(pack('<II', DepotManifest.PROTOBUF_METADATA_MAGIC, len(part)))
        data.write(part)

        part = self.signature.SerializeToString()
        data.write(pack('<II', DepotManifest.PROTOBUF_SIGNATURE_MAGIC, len(part)))
        data.write(part)

        data.write(pack('<I', DepotManifest.PROTOBUF_ENDOFMANIFEST_MAGIC))

        if compress:
            zbuff = BytesIO()
            with ZipFile(zbuff, 'w', ZIP_DEFLATED) as zf:
                zf.writestr('zip', data.getvalue())

            return zbuff.getvalue()
        else:
            return data.getvalue()
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
            resp = CDNClient.cdn_cmd(self,'depot', '%s/manifest/%s/5/%s' % (depot_id, manifest_gid, manifest_request_code))
            savemanifest(resp.content,"{}_{}.manifest".format(depot_id,manifest_gid))
            manifest = self.DepotManifestClass(app_id, resp.content)
            serialized = manifest.serialize(True)
            savemanifest(serialized,"{}_{}_zip.manifest".format(depot_id,manifest_gid))
            manifest.decrypt_filenames(self.get_depot_key(app_id, depot_id))
            serialized = manifest.serialize(True)
            savemanifest(serialized,"{}_{}_decrypted_zip.manifest".format(depot_id,manifest_gid))
            serialized = manifest.serialize(False)
            savemanifest(serialized,"{}_{}_decrypted.manifest".format(depot_id,manifest_gid))
        else:
            print("manifest already exist, we dont do much here!")
    
    def get_based(self, app_id, depot_id, manifest_gid):
        fp = open("{}_{}_decrypted.manifest".format(depot_id,manifest_gid),"rb")
        manifest = self.DepotManifestClass(app_id, fp.read())
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
    maps.chunks.sort(key=lambda x: x.offset, reverse=False)
    #print(maps)
    print(maps.filename)
    for chunk in maps.chunks:
        shahex = chunk.sha.hex()
        if not os.path.isfile(args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex)):
            resp = CDNClient.cdn_cmd(basedCDN,'depot', '%s/chunk/%s' % (depot_id, shahex))
            savechunk(resp.content, args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex))
            data = symmetric_decrypt(resp.content, CDNClient.get_depot_key(basedCDN, appid, depot_id))
            savechunk(data, args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex) + "_decrypted")
            if data[:2] == b'VZ':
                if data[-2:] != b'zv':
                    raise SteamError("VZ: Invalid footer: %s" % repr(data[-2:]))
                if data[2:3] != b'a':
                    raise SteamError("VZ: Invalid version: %s" % repr(data[2:3]))

                vzfilter = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[7:12])
                vzdec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[vzfilter])
                checksum, decompressed_size = struct.unpack('<II', data[-10:-2])
                # decompress_size is needed since lzma will sometime produce longer output
                # [12:-9] is need as sometimes lzma will produce shorter output
                # together they get us the right data
                data = vzdec.decompress(data[12:-9])[:decompressed_size]
                if crc32(data) != checksum:
                    raise SteamError("VZ: CRC32 checksum doesn't match for decompressed data")
            else:
                with ZipFile(BytesIO(data)) as zf:
                    data = zf.read(zf.filelist[0])
            savechunk(data, args.path + "\\" + str(appid)+ "\\" + str(depot_id)+"\\" + str(shahex) + "_decompressed")
