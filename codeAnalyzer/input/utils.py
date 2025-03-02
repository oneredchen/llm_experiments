import asyncio
import vt


async def ipScan(client, queries):
    tasks = []
    for query in queries:
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/ip_addresses/{query}"))
    # Execute the tasks in the task queue cocurrently
    ipResponses = await asyncio.gather(*tasks, return_exceptions=True)
    for resp in ipResponses:
        try:
            ipScanned = resp.id
            vtAnalysis = resp.last_analysis_stats
            print("-"*100)
            print(f"IP Scanned: {ipScanned}")
            print(
                f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
            print("-"*100)
        except Exception as e:
            print(f"Exception occurred: {e}")


async def urlScan(client, queries):
    unscannedURL = []
    tasks = []
    for query in queries:
        url_id = vt.url_id(query)
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/urls/{url_id}"))
        unscannedURL.append(query+"/")
    # Execute the tasks in the task queue cocurrently
    urlResponses = await asyncio.gather(*tasks, return_exceptions=True)
    for resp in urlResponses:
        try:
            urlScanned = resp.url
            unscannedURL.remove(urlScanned)
            vtAnalysis = resp.last_analysis_stats
            print("-"*100)
            print(f"URL Scanned: {urlScanned}")
            print(
                f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
            print("-"*100)
        except Exception as e:
            pass
    # Do detailed scan of URL if existing data not found on VT
    newTasks = []
    for unscan in unscannedURL:
        newTasks.append(client.scan_url_async(
            url=unscan, wait_for_completion=True))
    newScanResponses = await asyncio.gather(*newTasks, return_exceptions=True)
    for resp in newScanResponses:
        urlScanned = unscannedURL[0]
        try:
            unscannedURL.remove(urlScanned)
            vtAnalysis = resp.stats
            print("-"*100)
            print(f"URL Scanned: {urlScanned}")
            print(
                f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
            print("-"*100)
        except Exception as e:
            print(f"Exception occured: {e}")


async def fileScan(client, queries):
    tasks = []
    for query in queries:
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/files/{query}"))
    # Execute the tasks in the task queue cocurrently
    fileResponses = await asyncio.gather(*tasks, return_exceptions=True)
    for resp in fileResponses:
        try:
            print("-"*100)
            if resp.md5 in queries:
                print(f"MD5 Hash Scanned: {resp.md5}")
            elif resp.sha1 in queries:
                print(f"SHA1 Hash Scanned: {resp.sha1}")
            else:
                print(f"SHA256 Hash Scanned: {resp.sha256}")
            vtAnalysis = resp.last_analysis_stats
            print(
                f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
            print("-"*100)
        except Exception as e:
            print(f"Exception occurred: {e}")