# -*- coding: utf-8 -*-
"""
Created on Mon Feb 19 03:28:05 2018

@author: methylDragon
"""

"""
Dependencies:

- pythonwhois
    - Install: pip install pythonwhois
    - Docs: https://github.com/joepie91/python-whois

- dns.resolver
    - Install: pip install dnspython
    - Docs: http://www.dnspython.org/

- geoip2 (with geolite2 database)
    - Install: pip install geoip2
    - Database Downloads: https://dev.maxmind.com/geoip/geoip2/geolite2/
    - Docs: https://pypi.org/project/geoip2/

Additional notes:
    The geolite2 databases can be automatically updated!
    Set a cron task here: https://dev.maxmind.com/geoip/geoipupdate/
"""

import pythonwhois
import socket
import dns.resolver
import geoip2.database
import requests
import os

import tarfile

def sanitise_urls(url):
    """ Remove http(s) and www prefixes to URLs """
    # Strip https and http
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]

    # Strip www
    if url.startswith("www."):
        return url[4:]
    else:
        return url

def update_geolite_dbs():
    db_info_dict = {'GeoLite2_DBs/GeoLite2-City.mmdb' : 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz',
                    'GeoLite2_DBs/GeoLite2-Country.mmdb' : 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz',
                    'GeoLite2_DBs/GeoLite2-ASN.mmdb' : 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz'}

    try:
        os.mkdir('GeoLite2_DBs')
    except:
        pass

    for file, file_url in db_info_dict.items():
        print("Downloading", file)
        download = requests.get(file_url, stream=True)
        tar_location = "{}.gz".format(file)

        with open(tar_location,'wb') as f:
            for chunk in download.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    f.flush()

        tar = tarfile.open(tar_location, "r:gz")

        for member in tar.getmembers():
            if "mmdb" in member.name:
                member.name = os.path.basename(member.name)
                print("Extracting", member.name)
                tar.extract(member, path='GeoLite2_DBs/')

        tar.close()

def initialise_readers(path='GeoLite2_DBs/'):
    city_reader = geoip2.database.Reader(path + 'GeoLite2-City.mmdb')
    country_reader = geoip2.database.Reader(path + 'GeoLite2-Country.mmdb')
    asn_reader = geoip2.database.Reader(path + 'GeoLite2-ASN.mmdb')

    reader_dict = {"city": city_reader, "country": country_reader, "asn": asn_reader}

    return reader_dict

def probe_website(url, custom_dns_server="", geoip_readers=None):

    # Initialise output dicts
    output = {}

    domain_output = {}
    server_output = {"no_prefix": {"location_data": {} }, "www_prefix": {"location_data": {} } }

    # Save initial query
    output["initial_query"] = url

    # Sanitise inputs
    url = sanitise_urls(url)
    www_url = "www." + url

    # Query IPs
    ip = socket.gethostbyname(url)
    www_ip = socket.gethostbyname(www_url)

    # Grab DNS Info
    if custom_dns_server:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(custom_dns_server)]

        dns_info = resolver.query(url)
        www_dns_info = resolver.query(www_url)
    else:
        dns_info = dns.resolver.query(url)
        www_dns_info = dns.resolver.query(www_url)

    # Grab WHOIS Info
    whois_info = pythonwhois.get_whois(url)

    # Populate domain information
    domain_output["contacts"] = whois_info.get("contacts")
    domain_output["registrar"] = whois_info.get("registrar")[0]
    domain_output["nameservers"] = whois_info.get("nameservers")

    try:
        domain_output["creation_date_unix"] = whois_info.get("creation_date")[0].timestamp()
        domain_output["creation_date"] = whois_info.get("creation_date")[0].strftime('%Y-%m-%d %H-%M-%S')

        domain_output["last_update_date_unix"] = whois_info.get("updated_date")[0].timestamp()
        domain_output["last_update_date"] = whois_info.get("updated_date")[0].strftime('%Y-%m-%d %H-%M-%S')

        domain_output["expiration_date_unix"] = whois_info.get("expiration_date")[0].timestamp()
        domain_output["expiration_date"] = whois_info.get("expiration_date")[0].strftime('%Y-%m-%d %H-%M-%S')
    except:
        pass

    domain_output["query"] = url

    # Populate server information
    server_output["www_prefix"]["CNAME"] = str(dns_info.canonical_name)
    server_output["www_prefix"]["server_type"] = str(dns_info.canonical_name).split(".")[-3]
    server_output["www_prefix"]["ip"] = www_ip

    server_output["no_prefix"]["CNAME"] = str(www_dns_info.canonical_name)
    server_output["no_prefix"]["server_type"] = str(www_dns_info.canonical_name).split(".")[-3]
    server_output["no_prefix"]["ip"] = ip

    # Grab geo data
    if geoip_readers:
        city_reader = geoip_readers["city"]
        country_reader = geoip_readers["country"]
        asn_reader = geoip_readers["asn"]

        # Grab for www prefix
        server_output["www_prefix"]["query"] = www_url
        server_output["www_prefix"]["location_data"]["city"] = city_reader.city(www_ip).city.name
        server_output["www_prefix"]["location_data"]["postal_code"] = city_reader.city(www_ip).postal.code
        server_output["www_prefix"]["location_data"]["longitude"] = city_reader.city(www_ip).location.longitude
        server_output["www_prefix"]["location_data"]["latitude"] = city_reader.city(www_ip).location.latitude
        server_output["www_prefix"]["location_data"]["uncertainty_radius_km"] = city_reader.city(www_ip).location.accuracy_radius
        server_output["www_prefix"]["location_data"]["country"] = country_reader.country(www_ip).country.name
        server_output["www_prefix"]["network_operator"] = asn_reader.asn(www_ip).autonomous_system_organization

        # Grab for no prefix
        server_output["no_prefix"]["query"] = url
        server_output["no_prefix"]["location_data"]["city"] = city_reader.city(ip).city.name
        server_output["no_prefix"]["location_data"]["postal_code"] = city_reader.city(ip).postal.code
        server_output["no_prefix"]["location_data"]["longitude"] = city_reader.city(ip).location.longitude
        server_output["no_prefix"]["location_data"]["latitude"] = city_reader.city(ip).location.latitude
        server_output["no_prefix"]["location_data"]["uncertainty_radius_km"] = city_reader.city(ip).location.accuracy_radius
        server_output["no_prefix"]["location_data"]["country"] = country_reader.country(ip).country.name
        server_output["no_prefix"]["network_operator"] = asn_reader.asn(ip).autonomous_system_organization

    # Populate final output
    output["domain_info"] = domain_output
    output["server_info"] = server_output

    return output

# Example usage
if __name__ == "__main__":
    from pprint import pprint

    print("""=================
= EXAMPLE USAGE =
=================\n""")

    url = "methyldragon.com"

    print("QUERYING:", url, "\n")

    update_geolite_dbs()
    readers = initialise_readers()
    data = probe_website(url, geoip_readers = readers)

    pprint(data)