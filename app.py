from flask import Flask, request, jsonify, make_response
import requests
import binascii
import jwt
import urllib3
import json
import warnings
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

try:
    import my_pb2
    import output_pb2
except ImportError:
    pass


try:
    from byte import encrypt_api, Encrypt_ID
    from visit_count_pb2 import Info
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

DEFAULT_REGION = "IND"

MIDDLE_EAST_REGIONS = [
    "EUROPE", "MIDDLEEAST", "MIDDLE_EAST", "ME", "DUBAI", "UAE", "SAUDI",
    "SAUDIARABIA", "SAUDI_ARABIA", "KSA", "EGYPT", "EG", "TURKEY", "TR",
    "IRAQ", "IQ", "QATAR", "QA", "KUWAIT", "KW", "OMAN", "OM", "BAHRAIN",
    "BH", "JORDAN", "JO", "LEBANON", "LB", "SYRIA", "SY", "YEMEN", "YE",
    "PALESTINE", "PS", "ISRAEL", "IL", "CYPRUS", "CY", "GEORGIA", "GE",
    "ARMENIA", "AM", "AZERBAIJAN", "AZ", "IRAN", "IR", "AFGHANISTAN", "AF",
    "PAKISTAN", "PK", "NORTHAMERICA", "NA",
]

REGION_ALIASES = {
    "EUROPE": "ME", "MIDDLEEAST": "ME", "MIDDLE_EAST": "ME", "DUBAI": "ME",
    "UAE": "ME", "SAUDI": "ME", "SAUDIARABIA": "ME", "SAUDI_ARABIA": "ME",
    "KSA": "ME", "EGYPT": "ME", "EG": "ME", "TURKEY": "ME", "TR": "ME",
    "IRAQ": "ME", "IQ": "ME", "QATAR": "ME", "QA": "ME", "KUWAIT": "ME",
    "KW": "ME", "OMAN": "ME", "OM": "ME", "BAHRAIN": "ME", "BH": "ME",
    "JORDAN": "ME", "JO": "ME", "LEBANON": "ME", "LB": "ME", "SYRIA": "ME",
    "SY": "ME", "YEMEN": "ME", "YE": "ME", "PALESTINE": "ME", "PS": "ME",
    "ISRAEL": "ME", "IL": "ME", "CYPRUS": "ME", "CY": "ME", "GEORGIA": "ME",
    "GE": "ME", "ARMENIA": "ME", "AM": "ME", "AZERBAIJAN": "ME", "AZ": "ME",
    "IRAN": "ME", "IR": "ME", "AFGHANISTAN": "ME", "AF": "ME", "PAKISTAN": "ME",
    "PK": "ME", "NORTHAMERICA": "ME", "NA": "ME", "ASIA": "ME",
    "ASIA": "SG", "SOUTHAMERICA": "BR", "SOUTH_AMERICA": "BR",
    "NORTH_AMERICA": "NA", "LATAM": "BR",
}

REGION_MAP = {
    "IND": {
        "update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "ME": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "BD": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "PK": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "VN": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "SG": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "BR": {
        "update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "NA": {
        "update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "ID": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "RU": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
    "TH": {
        "update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
        "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin",
    },
}

FREEFIRE_VERSION = "OB54"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; Android)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION
}

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
b'\n\ndata.proto"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data1_pb2', _globals)

BioData = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')


def encrypt_data(data_bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)


def parse_major_login_response(response_content):
    try:
        example_msg = output_pb2.Garena_420()
        example_msg.ParseFromString(response_content)
        response_dict = {}
        lines = str(example_msg).split("\n")
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                response_dict[key.strip()] = value.strip().strip('"')
        return response_dict
    except Exception as e:
        return {"error": str(e)}


def perform_guest_login(uid, password):
    payload = {
        'uid': str(uid),
        'password': str(password),
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'ReleaseVersion': FREEFIRE_VERSION
    }
    try:
        resp = requests.post(OAUTH_URL, data=payload, headers=headers, verify=False, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if 'access_token' in data and 'open_id' in data:
                return data.get('access_token'), data.get('open_id')
    except Exception as e:
        print(f"Guest login error: {e}")
    return None, None


def perform_major_login(access_token, open_id, major_login_url):
    platforms = [8, 3, 4, 6]
    for platform_type in platforms:
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.126.1"
            game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game_data.device_type = "Handheld"
            game_data.network_provider = "Verizon Wireless"
            game_data.connection_type = "WIFI"
            game_data.screen_width = 1280
            game_data.screen_height = 960
            game_data.dpi = "240"
            game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game_data.total_ram = 5951
            game_data.gpu_name = "Adreno (TM) 640"
            game_data.gpu_version = "OpenGL ES 3.0"
            game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game_data.ip_address = "172.190.111.97"
            game_data.language = "en"
            game_data.open_id = open_id
            game_data.access_token = access_token
            game_data.platform_type = platform_type
            game_data.field_99 = str(platform_type)
            game_data.field_100 = str(platform_type)

            serialized_data = game_data.SerializeToString()
            encrypted = encrypt_data(serialized_data)

            response = requests.post(major_login_url, data=encrypted, headers=LOGIN_HEADERS, verify=False, timeout=15)

            if response.status_code == 200:
                parsed = parse_major_login_response(response.content)
                jwt_token = parsed.get("token", "")
                if jwt_token and jwt_token not in ["", "N/A", "null"]:
                    return jwt_token
        except Exception as e:
            print(f"Major login error for platform {platform_type}: {e}")
            continue
    return None


def decode_jwt_full(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        uid = decoded.get("account_id")
        name = decoded.get("nickname")
        region = decoded.get("lock_region") or decoded.get("region") or decoded.get("noti_region")
        country = decoded.get("country_code")
        return {
            "uid": str(uid) if uid else None,
            "name": name,
            "region": region.upper() if region else None,
            "country": country,
            "raw": decoded
        }
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None


def is_middle_east(jwt_region):
    if not jwt_region:
        return False
    jwt_region = jwt_region.upper().strip()
    return jwt_region in MIDDLE_EAST_REGIONS


def map_region(jwt_region):
    if not jwt_region:
        return None
    
    jwt_region = jwt_region.upper().strip()
    
    if jwt_region in REGION_MAP:
        return jwt_region
    
    if jwt_region in REGION_ALIASES:
        return REGION_ALIASES[jwt_region]
    
    me_keywords = ["EAST", "EUROPE", "DUBAI", "SAUDI", "UAE", "ARAB", "GULF", "EMIRATES"]
    for keyword in me_keywords:
        if keyword in jwt_region:
            return "ME"
    
    for alias, mapped in REGION_ALIASES.items():
        if alias in jwt_region or jwt_region in alias:
            return mapped
    
    return None


def _add_region_param(url, region):
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["region"] = region
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment))


def get_region_urls(region):
    region = (region or "").upper().strip() or DEFAULT_REGION
    if region not in REGION_MAP:
        raise ValueError(f"Unsupported region: {region}")
    update_url = _add_region_param(REGION_MAP[region]["update_url"], region)
    major_url = _add_region_param(REGION_MAP[region]["major_login_url"], region)
    return region, update_url, major_url


def upload_bio_mapped_region(jwt_token, bio_text, jwt_region):
    mapped_region = map_region(jwt_region)
    
    if is_middle_east(jwt_region):
        mapped_region = "ME"
    
    if not mapped_region:
        return {
            "status": f"Error: Unknown region '{jwt_region}'",
            "code": 500,
            "bio": bio_text,
            "server_response": ""
        }, jwt_region, None, False
    
    try:
        _, update_url, _ = get_region_urls(mapped_region)
        result = upload_bio_request(jwt_token, bio_text, update_url)
        is_me = (mapped_region == "ME")
        return result, jwt_region, mapped_region, is_me
    except Exception as e:
        return {
            "status": f"Error: {str(e)}",
            "code": 500,
            "bio": bio_text,
            "server_response": ""
        }, jwt_region, mapped_region, (mapped_region == "ME")


def upload_bio_request(jwt_token, bio_text, update_url):
    try:
        data = BioData()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        data_bytes = data.SerializeToString()
        encrypted = encrypt_data(data_bytes)

        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"

        resp = requests.post(update_url, headers=headers, data=encrypted, verify=False, timeout=30)

        status = "Unknown"
        if resp.status_code == 200:
            status = "✅ Success"
        elif resp.status_code == 401:
            status = "❌ Unauthorized"

        raw_hex = binascii.hexlify(resp.content).decode()

        return {
            "status": status,
            "code": resp.status_code,
            "bio": bio_text,
            "server_response": raw_hex
        }

    except Exception as e:
        return {
            "status": str(e),
            "code": 500,
            "bio": bio_text,
            "server_response": ""
        }


@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.form.get("pass")
    access_token = request.args.get("access") or request.args.get("access_token") or request.form.get("access") or request.form.get("access_token")
    region = request.args.get("region") or request.form.get("region")

    if not bio:
        return jsonify({"status": "❌ Missing bio"}), 400

    final_jwt = None
    jwt_info = None
    jwt_region = None
    login_method = "Unknown"

    if jwt_token:
        login_method = "Direct JWT"
        final_jwt = jwt_token
        jwt_info = decode_jwt_full(final_jwt)
        if jwt_info:
            jwt_region = jwt_info.get("region")

    elif uid and password:
        login_method = "UID/Pass Login"
        
        acc_token, open_id = perform_guest_login(uid, password)
        
        if not acc_token or not open_id:
            return jsonify({"status": "❌ Guest Login Failed", "code": 401}), 401
        
        final_jwt = None
        for region_code in REGION_MAP.keys():
            try:
                _, _, major_url = get_region_urls(region_code)
                final_jwt = perform_major_login(acc_token, open_id, major_url)
                if final_jwt:
                    break
            except:
                continue
        
        if not final_jwt:
            return jsonify({"status": "❌ JWT Generation Failed - Invalid credentials or account banned", "code": 500}), 500
        
        jwt_info = decode_jwt_full(final_jwt)
        if jwt_info:
            jwt_region = jwt_info.get("region")

    elif access_token:
        login_method = "Access Token Login"
        return jsonify({"status": "❌ Access token login not implemented in this version"}), 400

    else:
        return jsonify({"status": "❌ Provide JWT, or UID/Pass"}), 400

    if not final_jwt:
        return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500

    if not jwt_region and jwt_info:
        jwt_region = jwt_info.get("region")
    
    if not jwt_region and region:
        jwt_region = region.upper().strip()
    
    if not jwt_region:
        jwt_region = DEFAULT_REGION

    result, original_region, mapped_region, is_middle_east_flag = upload_bio_mapped_region(final_jwt, bio, jwt_region)

    response_text = f"""CreDit => @narutocodexff
JoIn => @narutocodexofc
BiO => {bio}
CoDe => {result['code']}
CoUnTrY_CoDe => {jwt_info.get('country') if jwt_info else 'N/A'}
GeNeRaTeD_JwT => {final_jwt}
LoGiN_MetHoD => {login_method}
MaPpEd_ReGiOn => {mapped_region}
NaMe => {jwt_info.get('name') if jwt_info else 'N/A'}
SeRvEr_ReSpOnSe => {result['server_response']}
StAtUs => {result['status']}
UiD => {jwt_info.get('uid') if jwt_info else 'N/A'}"""

    response = make_response(response_text)
    response.headers["Content-Type"] = "text/plain"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)