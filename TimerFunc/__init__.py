import logging
import re
import os
import sys
import requests
import configparser
import feedparser
import traceback
import azure.functions as func
from bs4 import BeautifulSoup
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.identity import DefaultAzureCredential

RSS_FEED = "https://www.us-cert.gov/ncas/analysis-reports.xml"
AZURE_BLOB_CONNECTION_STRING = ""
AZURE_STORAGE_ACCOUNT_CONTAINER = "stixfiles"

"""
def config_file():
    config = configparser.RawConfigParser()
    config.read('config.ini')
    AZURE_BLOB_CONNECTION_STRING = config.get('AZURE', 'az_blob_conn_string')
    AZURE_STORAGE_ACCOUNT_CONTAINER = config.get('AZURE', 'az_sa_container')
"""


def get_bearer_token(resource_uri = "https://graph.microsoft.com/beta/security/tiIndicators"):
    identity_endpoint = os.environ["IDENTITY_ENDPOINT"]
    identity_header = os.environ["IDENTITY_HEADER"]
    token_auth_uri = f"{identity_endpoint}?resource={resource_uri}&api-version=2019-08-01"
    head_msi = {'X-IDENTITY-HEADER':identity_header}

    resp = requests.get(token_auth_uri, headers=head_msi)
    access_token = resp.json()['access_token']

    return access_token

def upload_file_az_sa(blob_service_client, filename, stix_xml_url):
    filename = filename.replace(":","_").replace(" ","_").replace("__","_")
    upload_file_path = os.path.join(os.getcwd(),filename)
    """
    print(upload_file_path)

    file = open(upload_file_path,"w")
    file.write(stix_data)
    file.close()
    """
    # Create a blob client using the local file name as the name for the blob
    blob_client = blob_service_client.get_blob_client(container=AZURE_STORAGE_ACCOUNT_CONTAINER, blob=filename)

    print("Uploading to Azure Storage as blob: " + upload_file_path)

    # Upload the created file

    #blob_client.stage_block_from_url(filename, stix_xml_url)
    blob_client.copy_blob(AZURE_STORAGE_ACCOUNT_CONTAINER,filename,stix_xml_url)

def check_file_processed_az_sa(filename, stix_data, stix_xml_url):

    # Instantiate a BlobServiceClient using a connection string
    try:
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient("https://ststix.blob.core.windows.net/stixfiles", credential=credential)
        #blob_service_client = BlobServiceClient.from_connection_string(AZURE_BLOB_CONNECTION_STRING)

        # Instantiate a ContainerClient
        container_client = blob_service_client.get_container_client(AZURE_STORAGE_ACCOUNT_CONTAINER)

        blob_list = container_client.list_blobs()
        if blob_list.by_page().results_per_page is None:
            print("DEF-check_file_processed_az_sa-Information : No files within the container")
            upload_file_az_sa(blob_service_client, filename, stix_xml_url)
        else: 
            for blob in blob_list:
                if blob.name == filename:
                    print("DEF-check_file_processed_az_sa-Information : File already present within the container")
                else:
                    upload_file_az_sa(blob_service_client, filename, stix_xml_url)
    except Exception as error:
        print("DEF-check_file_processed_az_sa-Information : ", error)


def find_hashing_algo(hash, obs):
    if len(hash) == 64:
        obs["SHA256"] = hash
    if len(hash) == 128:
        obs["SHA512"] = hash
    else:
        obs["SSDEEP"] = hash
    return obs


def initilize_observable(metadata):
    obs = {}
    obs["usable"] = False
    obs["tlpLevel"] = "white"
    obs["lastReportedDateTime"] = metadata["lastReportedDateTime"]
    return obs

def parse_ip_address_observable(raw_observable, parsed_observable):
    parsed_observable["usable"] = True
    parsed_observable["Type"] = "IP"
    if raw_observable.contents[1].name == "cybox:properties":
        IP = raw_observable.contents[1].get_text()
        parsed_observable["networkDestinationIPv4"] = IP.replace("\n","")
    return (parsed_observable)


def parse_win_exec_observable(raw_observable, parsed_observable):
    parsed_observable["usable"] = True
    parsed_observable["Type"] = "Executable"

    #if raw_observable.contents[1].name == "cybox:properties":
    for file_properties in raw_observable.contents[1].descendants:
        file_properties_string = str(file_properties)
        if "fileobj:file_name" in file_properties_string:
            parsed_observable["fileName"] = file_properties.get_text()

        elif "fileobj:size_in_bytes" in file_properties_string:
            # Size of the file in bytes.
            parsed_observable["fileSize"] = int(file_properties.get_text())

        elif "fileobj:file_format" in file_properties_string:
            # Text description of the type of file. 
            # For example, “Word Document” or “Binary”.
            parsed_observable["fileType"] = file_properties.get_text()

        if "cyboxcommon:hash" in file_properties_string:
            for hashes in file_properties.descendants:

                if hashes.name == "cyboxcommon:type":
                    for child3 in hashes.children:
                        # We only keep:
                        # SH256: Used by Microsoft Defender ATP 
                        # SSDEEP: Used to perform Threat Hunting
                        if child3 in ("MD5","SHA1"):
                            break

                if hashes!=None and hashes.name=="cyboxcommon:simple_hash_value":
                    # Hash Value
                    # I don't want the MD5
                    if len(hashes.get_text()) <= 40:
                        break
                    else:
                        parsed_observable = find_hashing_algo(hashes.get_text(),
                                                              parsed_observable)
                        
    return (parsed_observable)

def get_STIX_data(stixurl):
    data = None
    try:
        r = requests.get(stixurl)
        data = r.text
    except Exception as error:
        print("Unexpected Error : ", error)
    return (data)

def parse_STIX(stixurl, title):
    #print(stixurl.decode("ascii"))
    try:
        r = requests.get(stixurl)
        data = r.text
    except Exception as error:
        print("Unexpected Error : ", error)

    soup = BeautifulSoup(data, 'html.parser')
    # Remove the TTPs part
    soup.find('stix:ttps').decompose()

    # Removing both "WinExecutableFileObj:Headers" and "WinExecutableFileObj:Sections"
    if (soup.find("winexecutablefileobj:headers")):
        soup.find("winexecutablefileobj:sections").decompose()

    timecreated = soup.find("stixcommon:time").get_text().replace("\n","")
    metadata = {}
    metadata["lastReportedDateTime"] = timecreated


    for raw_observable in soup.findAll(['cybox:observable',
                                    'cybox:object']):
        parsed_observable = initilize_observable(metadata)
        parsed_observable["description"] = title
        
        # Windows Executable
        if raw_observable.get('id').startswith("NCCIC:WinExecutableFile"):
            parsed_observable = parse_win_exec_observable(raw_observable,parsed_observable)

        # IP addresses
        elif raw_observable.get('id').startswith("NCCIC:Address"):
            parsed_observable = parse_ip_address_observable(raw_observable,parsed_observable)
        
        elif raw_observable.get('id').startswith("NCCIC:WhoisEntry"):
            pass
    
        elif raw_observable.get('id').startswith("NCCIC:WhoisEntry"):
            pass
        
        elif raw_observable.get('id').startswith("NCCIC:Port"):
            pass
        
        if parsed_observable["usable"]:
            pass
            #print(parsed_observable)

def processUS_CertRSS():
    feed = feedparser.parse(RSS_FEED)
    #config_file()
    for entry in feed.entries:
        stixFile = (re.search(b"(https:\/\/www.us-cert.gov\/sites)(.*)stix.xml",entry.description.encode("utf8")))
        if stixFile is not None:
            stix_xml_url = stixFile.group(0)
            title = entry.title
            stix_data = get_STIX_data(stix_xml_url)
            if stix_data is not None:
                xml_tile = title+".xml"
                check_file_processed_az_sa(xml_tile, stix_data, stix_xml_url)
                parse_STIX(stix_xml_url,title)

def main(mytimer: func.TimerRequest) -> None:
    processUS_CertRSS()
    
    """
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello {name}!")
    else:
        return func.HttpResponse(
             "Please pass a name on the query string or in the request body",
             status_code=400
        )
    """
