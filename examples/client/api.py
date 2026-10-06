"""Call the two-profile example app from an authorized tailnet device.

Install: pip install 'bytebind[requests]'
Replace the origin below with the API's public HTTPS origin.
"""

from bytebind.requests import Session


with Session("https://app.example.com") as api:
    # Lease: the client establishes a session and renews it as needed.
    response = api.get("/status")
    response.raise_for_status()
    print(response.json())

    # Transaction: one approval covers this exact request, independently of the lease.
    response = api.transaction("/restart", json={"service": "demo"})
    response.raise_for_status()
    print(response.json())

    api.logout()
