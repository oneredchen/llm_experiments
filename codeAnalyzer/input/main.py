import vt
import os
import re
import asyncio
from util import *


async def main():
    # Reading input file containing the queries to be made
    # Ensuring all required files are present & setup
    cwd = os.getcwd()
    inputFilename = "input.txt"
    if not os.path.exists(cwd + "/" + inputFilename):
        print("Please create an Input.txt file containing the URLs / File Hashes / IP address to be scanned")
        exit()
    apiKey = "INPUT YOUR OWN API KEY"
    ipRegex = "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$"
    urlRegex = re.compile(
        "((http|https)://)(www.)?" +
        "[a-zA-Z0-9@:%._\\+~#?&//=]" +
        "{2,256}\\.[a-z]" +
        "{2,6}\\b([-a-zA-Z0-9@:%" +
        "._\\+~#?&//=]*)")
    try:
        with open(inputFilename, 'r', encoding="utf-8") as file:
            queries = file.read().split()
    except:
        print("Error occurred with reading the file")
    # 3 separate tasks queue: IP, URL, Files (SHA256, SHA1 etc)
    ipQueries = []
    urlQueries = []
    fileQueries = []

    for query in queries:
        if re.search(ipRegex, query):
            # Identify if input is an IPv4 address
            ipQueries.append(query)
        elif re.search(urlRegex, query):
            urlQueries.append(query)
        else:
            fileQueries.append(query)
    print(
        f"IPv4 Query Queue: {ipQueries}\nURL Query Queue: {urlQueries}\nFile Query Queue: {fileQueries}")
    client = vt.Client(apiKey)
    await asyncio.gather(ipScan(client, ipQueries), urlScan(client, urlQueries),
                         fileScan(client, fileQueries))
    await client.close_async()

if __name__ == "__main__":
    asyncio.run(main())