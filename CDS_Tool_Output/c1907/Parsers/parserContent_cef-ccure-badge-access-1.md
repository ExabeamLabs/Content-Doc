#### Parser Content
```Java
{
Name = cef-ccure-badge-access-1
   Vendor = CCURE
   Product = CCURE
   Lms = ArcSight
   DataType = "physical-access"
   TimeFormat = "epoch"
   Conditions = ["""CEF:""", """|C-CURE|""", """|Card"""]
   Fields = [
     """src=({host}[^\s]+)""",
     """({outcome}Card (Rejected|Admitted))""",
     """\|start=({time}\d+)""",
     """\ssuid=(?:Unknown|(({domain}[^\\]+)\\?)?({user}.+?))\s(\w+=|$)""",
     """\ssuser=(?:|({user_fullname}.+?))\s(\w+=|$)""",
     """\scs1=(?:|({location_door}.+?))\s(\w+=|$)""",
     """\scs3=(?:|({location_city}.+?))\s(\w+=|$)"""
   ]
 }
```