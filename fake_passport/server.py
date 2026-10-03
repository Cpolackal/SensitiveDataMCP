"""Fake EHR MCP server returning SYNTHETIC patient data (Faker, fixed seed).

Deliberately includes PHI in both structured fields and free-text notes so the
proxy's redaction has something realistic to catch. No real data is used.
"""

from faker import Faker
from mcp.server.mcpserver import MCPServer

fake = Faker("en_US")
Faker.seed(1234)


def _make_patient(i: int) -> dict:
    name = fake.name()
    phone = fake.phone_number()
    return {
        "patient_id": f"P{1000 + i}",
        "name": name,
        "dob": fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
        "ssn": fake.ssn(),
        "email": fake.email(),
        "phone": phone,
        "address": fake.address().replace("\n", ", "),
        "labs": [
            {"test": "HbA1c", "value": round(fake.pyfloat(min_value=4.5, max_value=11), 1), "unit": "%"},
            {"test": "LDL", "value": fake.random_int(60, 190), "unit": "mg/dL"},
        ],
        # Free-text note: PHI embedded in prose, where field-name redaction can't help.
        "notes": (
            f"Pt {name} called from {phone} re: refill. "
            f"Follow-up emailed to {fake.email()}. SSN on file {fake.ssn()}."
        ),
    }


PATIENTS = [_make_patient(i) for i in range(10)]

mcp = MCPServer("fake-ehr")


@mcp.tool()
def search_patients(query: str) -> list[dict]:
    """Search patients by name; returns id and name."""
    q = query.lower()
    return [
        {"patient_id": p["patient_id"], "name": p["name"]}
        for p in PATIENTS
        if q in p["name"].lower()
    ]


@mcp.tool()
def get_patient(patient_id: str) -> dict:
    """Get the full record for one patient."""
    for p in PATIENTS:
        if p["patient_id"] == patient_id:
            return p
    raise ValueError(f"No patient {patient_id}")


@mcp.tool()
def get_lab_results(patient_id: str) -> list[dict]:
    """Get lab results for one patient."""
    return get_patient(patient_id)["labs"]


if __name__ == "__main__":
    mcp.run()
