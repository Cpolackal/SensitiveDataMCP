"""Fake passport-records MCP server returning SYNTHETIC traveler data (Faker, fixed seed).

Deliberately includes PII in structured fields, in a machine-readable-zone (MRZ)
style string, and in free-text notes so the proxy's redaction has something
realistic to catch. No real data is used.
"""

from faker import Faker
from mcp.server.mcpserver import MCPServer

fake = Faker("en_US")
Faker.seed(1234)


def _mrz(surname: str, given: str, passport_no: str, dob, expiry, sex: str) -> list[str]:
    """Approximation of a TD3 MRZ for realism. Check digits are not computed."""
    line1 = f"P<USA{surname.upper()}<<{given.upper().replace(' ', '<')}".ljust(44, "<")
    line2 = f"{passport_no}<0USA{dob:%y%m%d}0{sex}{expiry:%y%m%d}0".ljust(44, "<")
    return [line1[:44], line2[:44]]


def _make_traveler(i: int) -> dict:
    given, surname = fake.first_name(), fake.last_name()
    name = f"{given} {surname}"
    sex = fake.random_element(["M", "F"])
    dob = fake.date_of_birth(minimum_age=18, maximum_age=80)
    issued = fake.date_between(start_date="-9y", end_date="-1y")
    expiry = issued.replace(year=issued.year + 10)
    passport_no = fake.passport_number()
    phone = fake.phone_number()
    return {
        "traveler_id": f"T{1000 + i}",
        "name": name,
        "passport_number": passport_no,
        "nationality": "USA",
        "dob": dob.isoformat(),
        "sex": sex,
        "place_of_birth": f"{fake.city()}, {fake.state_abbr()}",
        "issue_date": issued.isoformat(),
        "expiry_date": expiry.isoformat(),
        "ssn": fake.ssn(),
        "email": fake.email(),
        "phone": phone,
        "address": fake.address().replace("\n", ", "),
        "mrz": _mrz(surname, given, passport_no, dob, expiry, sex),
        "visa_history": [
            {"country": fake.country(), "visa_type": fake.random_element(["B1/B2", "F1", "H1B", "ESTA"]),
             "expires": fake.date_between(start_date="+30d", end_date="+3y").isoformat()}
            for _ in range(fake.random_int(1, 3))
        ],
        # Free-text note: PII embedded in prose, where field-name redaction can't help.
        "notes": (
            f"{name} called from {phone} to renew passport {passport_no}. "
            f"Confirmation emailed to {fake.email()}. SSN on file {fake.ssn()}."
        ),
    }


TRAVELERS = [_make_traveler(i) for i in range(10)]

mcp = MCPServer("fake-passport")


@mcp.tool()
def search_travelers(query: str) -> list[dict]:
    """Search travelers by name; returns id and name."""
    q = query.lower()
    return [
        {"traveler_id": t["traveler_id"], "name": t["name"]}
        for t in TRAVELERS
        if q in t["name"].lower()
    ]


@mcp.tool()
def get_passport(traveler_id: str) -> dict:
    """Get the full passport record for one traveler."""
    for t in TRAVELERS:
        if t["traveler_id"] == traveler_id:
            return t
    raise ValueError(f"No traveler {traveler_id}")


@mcp.tool()
def get_visa_history(traveler_id: str) -> list[dict]:
    """Get visa history for one traveler."""
    return get_passport(traveler_id)["visa_history"]


if __name__ == "__main__":
    mcp.run()
