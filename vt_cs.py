
import vt
import time
import csv

API_KEY = "<Virus Total API>"  # Replace with your actual API key
OUTPUT_CSV = "not_detected_by_crowdstrike.csv"
MAX_RESULTS = 500  # Adjust as per your API quota
BATCH_SIZE = 4     # Public API allows 4 requests per minute
DUMP_INTERVAL = 300  # 5 minutes in seconds

# Categories that indicate detection by CrowdStrike Falcon
DETECTION_CATEGORIES = {"malicious", "suspicious", "phishing", "malware", "grayware", "ransomware"}

def dump_results(results, filename):
    print(f"Number of results to write: {len(results)}")
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["Hash"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"Intermediate dump: {len(results)} results saved to {filename}")

def main():
    client = vt.Client(API_KEY)
    results = []

    query = "fs:2024-07-09+"
    iterator = client.iterator("/intelligence/search", params={"query": query})

    count = 0
    last_dump = time.time()

    for file_obj in iterator:
        if count and count % BATCH_SIZE == 0:
            print("Sleeping to respect API rate limits...")
            time.sleep(60)

        analysis = file_obj.get("last_analysis_results", {})
        cs_result = analysis.get("CrowdStrike Falcon")

        # Include if not scanned or not detected in any form
        if cs_result is None or cs_result.get("category", "").lower() not in DETECTION_CATEGORIES:
            results.append({"Hash": file_obj.id})

        count += 1

        if time.time() - last_dump >= DUMP_INTERVAL:
            dump_results(results, OUTPUT_CSV)
            last_dump = time.time()

        if count >= MAX_RESULTS:
            break

    dump_results(results, OUTPUT_CSV)
    print(f"Done. {len(results)} results saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
