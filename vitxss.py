import requests
import subprocess
import argparse
import re
import json
from urllib.parse import urlparse
from colorama import Fore, init

init()


class Scanner:
    def __init__(self, filename, output):
        self.filename = filename
        self.output = output
    
    @staticmethod
    def read(filename):
        print(f'{Fore.WHITE}READING URLS')

        with open(filename, 'r') as urls_file:
            urls = urls_file.read().splitlines()

        return urls

    @staticmethod
    def write(output, value):
        subprocess.call(f'echo "{value}" >> {output}', shell=True)

    @staticmethod
    def replace(url, param, value):
        return re.sub(f'{param}=([^&]+)', f'{param}={value}', url)

    @staticmethod
    def bubble_sort(arr):
        a = 0
        keys = []

        for i in arr:
            for j in i:
                keys.append(j)

        while a < len(keys) - 1:
            b = 0

            while b < len(keys) - 1:
                d1 = arr[b]
                d2 = arr[b + 1]

                if len(d1[keys[b]]) < len(d2[keys[b + 1]]):
                    d = d1

                    arr[b] = arr[b + 1]

                    arr[b + 1] = d

                    z = keys[b + 1]

                    keys[b + 1] = keys[b]

                    keys[b] = z

                b += 1

            a += 1

        return arr

    @staticmethod
    def parameters(url):
        param_names = []
        params = urlparse(url).query
        params = params.split('&')
        params = list(filter(lambda param: '=' in param, params))

        if len(params) == 1:
            params = params[0].split('=')
            param_names.append(params[0])

        else:
            for param in params:
                param = param.split('=')

                param_names.append(param[0])

        return param_names

    @staticmethod
    def parser(url, param, value):
        final_parameters = {}
        parsed_data = urlparse(url)
        params = parsed_data.query
        protocol = parsed_data.scheme
        hostname = parsed_data.hostname
        path = parsed_data.path
        params = params.split('&')

        if len(params) == 1:
            params = params[0].split('=')
            final_parameters[params[0]] = params[1]

        else:
            for param in params:
                param = param.split('=')

                final_parameters[param[0]] = param[1]

        final_parameters[param] = value

        return final_parameters

    @staticmethod
    def filter_payload(arr):
        payload_list = []
        size = int(len(arr) / 2)

        print(f'{Fore.WHITE}[+] LOADING PAYLOAD FILE payloads.json')

        with open('payloads.json') as payloads_file:
            payloads = json.load(payloads_file)

        for char in arr:
            for payload in payloads:
                attributes = payload['Attribute']

                if char in attributes:
                    payload['count'] += 1

        payloads.sort(key=lambda e: e['count'], reverse=True)

        for payload in payloads:
            if payload['count'] == len(arr) == len(payload['Attribute']):
                print(Fore.GREEN + f'[+] FOUND SOME PERFECT PAYLOADS FOR THE TARGET')

                payload_list.insert(0, payload['Payload'])

                continue

            if payload['count'] > size:
                payload_list.append(payload['Payload'])

                continue

        return payload_list

    def validator(self, arr, param, url):
        params = {
            param: []
        }

        try:
            for data in arr:
                final_parameters = self.parser(url, param, data + 'randomstring')
                new_url = urlparse(url).scheme + '://' + urlparse(url).hostname + '/' + urlparse(url).path
                response = requests.get(new_url, params=final_parameters).text

                if data + 'randomstring' in response:
                    print(f'{Fore.GREEN}[+] {data} is reflecting in the response')

                    params[param].append(data)
        except Exception as e:
            print(e)

        return params

    def fuzzer(self, url):
        data = []
        dangerous_characters = [
            '>',
            ''',
            ''',
            '<',
            '/',
            ';'
        ]

        parameters = self.parameters(url)

        print(f'[+] {len(parameters)} parameters identified')

        for parameter in parameters:
            print(f'[+] Testing parameter name: {parameter}')

            out = self.validator(dangerous_characters, parameter, url)

            data.append(out)

        print('[+] FUZZING HAS BEEN COMPLETED')

        return self.bubble_sort(data)

    def scanner(self, url):
        out = self.fuzzer(url)

        for data in out:
            for key in data:
                payload_list = self.filter_payload(data[key])

            for payload in payload_list:
                try:
                    data = self.parser(url, key, payload)
                    parsed_data = urlparse(url)
                    new_url = parsed_data.scheme + '://' + parsed_data.netloc + '/' + parsed_data.path
                    response = requests.get(new_url, params=data).text

                    if payload in response:
                        print(f'{Fore.RED}[+] VULNERABLE: {url}\nPARAMETER: {key}\nPAYLAOD USED: {payload}')

                        return self.replace(url, key, payload)
                except Exception as e:
                    print(e)

        print(f'{Fore.LIGHTWHITE_EX}[+] TARGET SEEMS TO BE NOT VULNERABLE')

        return


parser = argparse.ArgumentParser(description='VitInspect')
parser.add_argument('-f', '--filename', help='Input file', required=True)
parser.add_argument('-o', '--output', help='Output file', required=True)
args = parser.parse_args()

try:
    scanner = Scanner(args.filename, args.output)
    urls = scanner.read(args.filename)

    for url in urls:
        print(f'{Fore.WHITE}[+] TESTING {url}')

        vuln = scanner.scanner(url)

        if vuln:
            scanner.write(output, vuln)

    print(f'{Fore.WHITE}[+] COMPLETED')
except KeyboardInterrupt:
    pass
