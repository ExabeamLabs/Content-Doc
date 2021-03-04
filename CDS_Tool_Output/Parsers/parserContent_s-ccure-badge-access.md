#### Parser Content
```Java
{
Name = s-ccure-badge-access
  Vendor = CCURE
  Product = CCURE
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """MessageType="Card""", """SecondaryObjectName="""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"\s+(\w+=|$)""",
    """,\s*ServerName="({host}[^"]+)""",
    """,\s*MessageType="({outcome}[^"]+)""",
    """,\s*Name="({user_fullname}[^"]+)"""",
    """,\s*Name="({last_name}[^",]+)\s*,\s*({first_name}[^"]+)"""",
    """,\s*CardNumber="({badge_id}\d+)""",
    """,\s*SecondaryObjectName="({location_door}[^"]+)"""",
    """,\s*ServerUTC="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """<Direction>\s*({direction}.+)\s*</Direction>""",
    """<Card>\s*({badge_id}\d+)\s*</Card>""",
    """<CHUID>\s*({badge_id}\d+)\s*</CHUID>""",
    """<PrimaryObjectName>\s*({last_name}[^,]+?),\s*({first_name}.*?)\s*</PrimaryObjectName>""",
    """<SecondaryObjectName>\s*({location_door}.+?)\s*</SecondaryObjectName>""",
    """<AdmitCode>\s*({outcome_reason}.+?)\s*</AdmitCode>""",
    """<RejectCode>\s*({outcome_reason}.+?)\s*</RejectCode>"""
  ]
}
```