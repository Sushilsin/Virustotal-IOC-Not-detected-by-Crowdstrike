import vt
import time
import csv

API_KEY = "<VT API>"  # Replace with your actual API key
OUTPUT_CSV = "malicious_by_any_not_crowdstrike.csv"
MAX_RESULTS = 500  # Adjust as per your API quota
BATCH_SIZE = 4     # Public API allows 4 requests per minute
DUMP_INTERVAL = 300  # 5 minutes in seconds

def dump_results(results, filename):
    print("Number of results to write: {}".format(len(results)))
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["Hash"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print("Intermediate dump: {} results saved to {}".format(len(results), filename))

def main():
    with vt.Client(API_KEY) as client:
        results = []
        query = "fs:2024-07-09+"
        iterator = client.iterator("/intelligence/search", params={"query": query})

        count = 0
        last_dump = time.time()

        for file_obj in iterator:
            if count and count % BATCH_SIZE == 0:
                print("Sleeping to respect API rate limits...")
                time.sleep(60)  # Sleep for 1 minute after every batch

            analysis = file_obj.get("last_analysis_results", {})
            cs_result = analysis.get("CrowdStrike")
            # Only include if CrowdStrike did NOT detect as malicious
            if cs_result is None or cs_result.get("category") != "malicious":
                # Check if any other engine detected as malicious
                detected_by_others = any(
                    (engine != "CrowdStrike" and result.get("category") == "malicious")
                    for engine, result in analysis.items()
                )
                if detected_by_others:
                    results.append({"Hash": file_obj.id})

            count += 1

            if time.time() - last_dump >= DUMP_INTERVAL:
                dump_results(results, OUTPUT_CSV)
                last_dump = time.time()

            if count >= MAX_RESULTS:
                break

        dump_results(results, OUTPUT_CSV)
        print("Done. {} results saved to {}".format(len(results), OUTPUT_CSV))

if __name__ == "__main__":
    main()
