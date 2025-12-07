import requests
import time

BASE_URL = "http://localhost:8000"

def test_api():
    print("Wait for server to start...")
    time.sleep(3)
    
    # 1. List cases (expect empty or existing)
    print("Testing GET /cases...")
    try:
        response = requests.get(f"{BASE_URL}/cases")
        print(f"Status: {response.status_code}")
        print(f"Data: {response.json()}")
    except Exception as e:
        print(f"Failed: {e}")
        return

    # 2. Create case
    print("\nTesting POST /cases...")
    case_name = "Refactor Test Case"
    response = requests.post(f"{BASE_URL}/cases", json={"name": case_name})
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Data: {data}")
    case_id = data.get("case_id")

    if case_id:
        # 3. Get case details
        print(f"\nTesting GET /cases/{case_id}...")
        response = requests.get(f"{BASE_URL}/cases/{case_id}")
        print(f"Status: {response.status_code}")
        print(f"Data: {response.json()}")
        
        # 4. Get case data
        print(f"\nTesting GET /cases/{case_id}/data...")
        response = requests.get(f"{BASE_URL}/cases/{case_id}/data")
        print(f"Status: {response.status_code}")
        print(f"Data keys: {response.json().keys()}")

        # 5. Delete case
        print(f"\nTesting DELETE /cases/{case_id}...")
        response = requests.delete(f"{BASE_URL}/cases/{case_id}")
        print(f"Status: {response.status_code}")
        print(f"Result: {response.json()}")

if __name__ == "__main__":
    test_api()
