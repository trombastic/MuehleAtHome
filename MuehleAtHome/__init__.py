import json
from datetime import datetime, timezone
import requests
import hmac
import base64
from Crypto.Cipher import AES # pycryptodome, pycrypto
from Crypto.Random import get_random_bytes # pycrypto is not working with python >= 3.8

__version__ = "0.0.1"

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
            msg=msg.encode("ASCII")).digest()
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
            header['X-Signature'] = "MieleH256" + self.group_id + ":" + signature # this is working

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
            msg=msg.encode("ASCII")).digest()
        return signature

    def commissioning(self):
        """comisioning and key exchange with the houshold applience

        this has to be done once to negociate the group_id and group_key with the
        houshold applience.
        If the device is already connected to the Miele@Mobile there are two options:
            - reset the device to be able to do a new commissioning (this will break all preavious connetions)
            - try to get the group_id and group_key from your mobile device
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
        )
        #fixme do something with the response (e.g. check return code and handle errors)

    def get_request(self, resource_path = ""):
        """request json data from the device
        """
        resource_path = "/" + resource_path
        r = requests.request("GET",
            url='http://%s%s'%(self.device_ip, resource_path),
            headers = self.make_header("GET", resource_path, content_header = "")[0],
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
        """parse the signiture string and split it into the three parts
        <ENCRYPTION_METHOD> <GROUP_ID>:<SIGNITURE>
        """
        encryption_method, packet_group_key = response.headers["X-Signature"].split(":")[0].split(" ")
        # paket signiture is the string (hex) after the ':'
        packet_signiture = response.headers["X-Signature"].split(":")[-1]
        return encryption_method, packet_group_key, packet_signiture

    def _crypt(self, packet_signiture):
        """AES_CBC encryption for the MieleH256 encryption
        """
        # first 32 bytes of the group key is the AES key for decryption
        aes_key = self._group_key_bytes[:32]
        # first 16 bytes of the signature of the response packet are the init vector for the decryption
        iv = bytes.fromhex(packet_signiture)[:16]
        return AES.new(aes_key, AES.MODE_CBC, iv)

    def encrypt(self, msg, packet_signiture):
        """encrypt a packet for PUT and POST payload
        """
        cipher = self._crypt(packet_signiture)
        return cipher.encrypt(msg)

    def decrypt(self, msg, packet_signiture):
        """decrypt payload of get requests
        """
        cipher = self._crypt(packet_signiture)
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

    def put_request(self, resource_path = ""):
        """request json data from the device
        """
        resource_path = "/" + resource_path
        payload = '{\n\t"DeviceName":"Test"\n\n}\n'
        header, packet_signature = self.make_header("PUT", resource_path, accept_header="", content_header = self.content_header, payload=payload)

        msg = payload.encode("ASCII")
        msg = msg + (16-(len(msg)%16)) * b'0' # add padding for len%16==0
        msg = self.encrypt(msg, packet_signature)
        r = requests.request("PUT",
            url='http://%s%s'%(self.device_ip, resource_path),
            headers = header,
            data = 12
        )
        if not r.ok:
            return r

        return r
