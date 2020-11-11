#### Parser Content
```Java
{
Name = q-ccure-badge-access
   Vendor = CCURE
   Product = CCURE
   Lms = QRadar
   DataType = "physical-access"
   TimeFormat = "yyyy-MM-dd HH:mm:ss"
   Conditions = [ """XmlMessage:""", """MessageType: "Card""", """PrimaryPartitionName:"""]
   Fields = [
     """exabeam_host=(?:.*@\s*)?({host}[^\s]+)""",
     """ServerUTC:\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """MessageType:\s*"({outcome}[^"]+)""",
     """<Direction>\s*({direction}.+)\s*</Direction>""",
     """<Card>\s*({badge_id}\d+)\s*</Card>""",
     """<PrimaryObjectName>\s*({last_name}[^,]+?),\s*({first_name}.*?)\s*</PrimaryObjectName>""",
     """<SecondaryObjectName>\s*({location_door}.+?)\s*</SecondaryObjectName>""",
     """PrimaryPartitionName:\s*"({user_city}[^"]+)""",
     """<AdmitCode>\s*({outcome_reason}.+?)\s*</AdmitCode>""",
     """<RejectCode>\s*({outcome_reason}.+?)\s*</RejectCode>"""
   ]
 }
```