#### Parser Content
```Java
{
Name = q-ccure-badge-access
   Vendor = Tyco
   Product = CCURE Building Management System
   Lms = QRadar
   DataType = "physical-access"
   TimeFormat = "yyyy-MM-dd HH:mm:ss"
   Conditions = [ """XmlMessage:""", """MessageType: "Card""", """PrimaryPartitionName:"""]
   Fields = [
     """exabeam_host=(?:.*@\s{0,100})?({host}[^\s]{1,2000})""",
     """ServerUTC:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """MessageType:\s{0,100}"({outcome}[^"]{1,2000})""",
     """<Direction>\s{0,100}({direction}.+)\s{0,100}</Direction>""",
     """<Card>\s{0,100}({badge_id}\d{1,100})\s{0,100}</Card>""",
     """<PrimaryObjectName>\s{0,100}({last_name}[^,]{1,2000}?),\s{0,100}({first_name}.*?)\s{0,100}</PrimaryObjectName>""",
     """<SecondaryObjectName>\s{0,100}({location_door}.+?)\s{0,100}</SecondaryObjectName>""",
     """PrimaryPartitionName:\s{0,100}"({user_city}[^"]{1,2000})""",
     """<AdmitCode>\s{0,100}({outcome_reason}.+?)\s{0,100}</AdmitCode>""",
     """<RejectCode>\s{0,100}({outcome_reason}.+?)\s{0,100}</RejectCode>"""
   ]
 }
```