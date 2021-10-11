#### Parser Content
```Java
{
Name = s-ccure-badge-access
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """MessageType="Card""", """SecondaryObjectName="""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"\s{1,100}(\w+=|$)""",
    """,\s{0,100}ServerName="({host}[^"]{1,2000})""",
    """,\s{0,100}MessageType="({outcome}[^"]{1,2000})""",
    """,\s{0,100}Name="({user_fullname}[^"]{1,2000})"""",
    """,\s{0,100}Name="({last_name}[^",]{1,2000})\s{0,100},\s{0,100}({first_name}[^"]{1,2000})"""",
    """,\s{0,100}CardNumber="({badge_id}\d{1,100})""",
    """,\s{0,100}SecondaryObjectName="({location_door}[^"]{1,2000})"""",
    """,\s{0,100}ServerUTC="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """<Direction>\s{0,100}({direction}.+)\s{0,100}</Direction>""",
    """<Card>\s{0,100}({badge_id}\d{1,100})\s{0,100}</Card>""",
    """<CHUID>\s{0,100}({badge_id}\d{1,100})\s{0,100}</CHUID>""",
    """<PrimaryObjectName>\s{0,100}({last_name}[^,]{1,2000}?),\s{0,100}({first_name}.*?)\s{0,100}</PrimaryObjectName>""",
    """<SecondaryObjectName>\s{0,100}({location_door}.+?)\s{0,100}</SecondaryObjectName>""",
    """<AdmitCode>\s{0,100}({outcome_reason}.+?)\s{0,100}</AdmitCode>""",
    """<RejectCode>\s{0,100}({outcome_reason}.+?)\s{0,100}</RejectCode>"""
  ]
}
```