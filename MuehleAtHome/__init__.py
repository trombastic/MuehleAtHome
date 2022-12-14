import json
from datetime import datetime, timezone
import requests
import hmac
import base64
from Crypto.Cipher import AES # pycryptodome, pycrypto
from Crypto.Random import get_random_bytes # pycrypto is not working with python >= 3.8

__version__ = "0.0.1"

request_timeout = 2.0

def http_date():
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

class MuehleDevice():
    user_agent = "Muehle@home %s Python" % (__version__)
    accept_header = "application/vnd.miele.v1+json"
    content_header = "application/vnd.miele.v1+json; charset=utf-8"

    def __init__(self,device_ip, group_id="1111111111111111", group_key=get_random_bytes(64).hex()):
        self.device_ip = device_ip # the IP Address of the Miele@Home Device
        self.group_id = group_id
        self._group_key = group_key # key for the AES signing and encryption
        self._group_key_bytes = bytes.fromhex(self.group_key)

    @property
    def group_key(self):
        """return the current group key as HEX string
        """
        return self._group_key

    @group_key.setter
    def group_key(self, value):
        """update the group key from hex string
        """
        #FIXME check length
        self._group_key = value
        self._group_key_bytes = bytes.fromhex(self.group_key)

    def make_signature(self, request_type, request_date, resource_path, accept_header=accept_header, content_header=content_header, payload=""):
        # generate signature HMAC SHA256
        msg = request_type + "\n"
        msg += self.device_ip + resource_path + "\n"
        msg += content_header + "\n"
        msg += accept_header + "\n"
        msg += request_date + "\n"
        msg += payload
        signature = hmac.new(
            self._group_key_bytes,
            digestmod="sha256",
            msg=msg.encode("utf-8")).digest()
        return signature

    def make_header(self, request_type, resource_path, accept_header=accept_header, content_header=content_header, payload=""):
        request_date = http_date()

        signature = self.make_signature(request_type, request_date, resource_path, accept_header, content_header, payload).hex().upper()

        header = {
                "Date": request_date,
                "User-Agent": self.user_agent,
                "Host": self.device_ip,
                "connection": "close",
            }
        if accept_header is not None and accept_header != "":
            header["Accept"] =  self.accept_header
            header["Accept-Encoding"] ="gzip"
            header["Authorization"] = "MieleH256 " + self.group_id + ":" + signature

        if content_header is not None and content_header != "":
            header['Content-Type'] = self.content_header
            header['X-Signature'] = "MieleH256 " + self.group_id + ":" + signature # this is working

        return header, signature

    def response_signature(self, response, payload, ):
        """calculates the signature for the response
        """
        msg =  str(response.status_code) + "\n"
        msg += response.headers['Content-Type'] + "\n"
        msg += response.headers['Date'] + "\n"
        msg += payload.decode()
        signature = hmac.new(
            self._group_key_bytes,
            digestmod="sha256",
            msg=msg.encode("utf-8")).digest()
        return signature

    def commissioning(self):
        """comisioning and key exchange with the household appliance

        This has to be done once to negotiate the group ID and group key with the
        houshold appliance.
        If the device is already connected to the Miele@Mobile there are two options:
            - reset the device to be able to do a new commissioning (this will break all previous connections)
            - try to get the group ID and group key from your mobile device
        """

        r = requests.request("PUT",
            url='http://%s/Security/Commissioning/'%self.device_ip,
            headers = {
                "Accept": self.accept_header,
                "Date": http_date(),
                "User-Agent": self.user_agent,
                "Host": self.device_ip,
                "Accept-Encoding":"gzip",
                'Content-Type': 'application/x-www-form-urlencoded',
                "connection": "close"
            },
            data='{"GroupID":"' + self.group_id + '","GroupKey":"'+ self.group_key + '"}',
            timeout=request_timeout,
        )
        #fixme do something with the response (e.g. check return code and handle errors)

    def get_request(self, resource_path = ""):
        """request json data from the device
        """
        resource_path = "/" + resource_path
        r = requests.request("GET",
            url='http://%s%s'%(self.device_ip, resource_path),
            headers = self.make_header("GET", resource_path, content_header = "")[0],
            timeout=request_timeout,
        )
        if not r.ok:
            return None

        encryption_method, packet_group_key, packet_signature = self.parse_signature(r)
        payload = self.decrypt(r.content, packet_signature)
        if self.response_signature(r, payload).hex().upper() != packet_signature:
            # todo throw signature error
            print(packet_signature)
            print(self.response_signature(r, payload).hex().upper())
            return None
        return payload

    @staticmethod
    def parse_signature(response):
        """parse the signature string and split it into the three parts
        <ENCRYPTION_METHOD> <GROUP_ID>:<SIGNATURE>
        """
        encryption_method, packet_group_key = response.headers["X-Signature"].split(":")[0].split(" ")
        # packet signature is the string (hex) after the ':'
        packet_signature = response.headers["X-Signature"].split(":")[-1]
        return encryption_method, packet_group_key, packet_signature

    def _crypt(self, packet_signature):
        """AES_CBC encryption for the MieleH256 encryption
        """
        # first 32 bytes of the group key is the AES key for decryption
        aes_key = self._group_key_bytes[:32]
        # first 16 bytes of the signature of the response packet are the init vector for the decryption
        iv = bytes.fromhex(packet_signature)[:16]
        return AES.new(aes_key, AES.MODE_CBC, iv)

    def encrypt(self, msg, packet_signature):
        """encrypt a packet for PUT and POST payload
        """
        cipher = self._crypt(packet_signature)
        return cipher.encrypt(msg)

    def decrypt(self, msg, packet_signature):
        """decrypt payload of get requests
        """
        cipher = self._crypt(packet_signature)
        return cipher.decrypt(msg)

    def get_endpoints(self, root=""):
        """list all endpoints
        """
        entpoints_dict = {}
        raw_json_str = self.get_request(root)
        if raw_json_str is None:
            return entpoints_dict
        json_data = json.loads(raw_json_str)
        for entry, data in json_data.items():
            if type(data) is dict and "href" in data:
                for key, value in self.get_endpoints(root+data["href"]).items():
                    entpoints_dict[key] = value
            else:
                entpoints_dict[root + ":" + entry] = data
        return entpoints_dict

    def device_info(self, fabnumber):
        """query the device info
        """
        raw_json_str = device.get_request('Devices/%s/State/'%fabnumber)
        json_data = json.loads(raw_json_str)
        return json_data

    def put_request(self, resource_path, payload):
        """send JSON data to the device"""

        resource_path = "/" + resource_path

        # pad payload to a multiple of 16 bytes for encryption
        msg = payload.encode("utf-8")
        msg = msg.ljust((len(msg) + 15) & ~15)
        msg = msg.decode()

        header, packet_signature = self.make_header("PUT", resource_path, accept_header=self.accept_header, content_header = self.content_header, payload=msg)

        msg = self.encrypt(msg, packet_signature)

        r = requests.request("PUT",
            url='http://%s%s'%(self.device_ip, resource_path),
            headers = header,
            data = msg,
            timeout=request_timeout,
        )

        if not r.ok:
            return None

        return r
