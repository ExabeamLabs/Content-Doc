#### Parser Content
```Java
{
Name = cef-ccure-badge-access-1
   Vendor = Tyco
   Product = CCURE Building Management System
   Lms = ArcSight
   DataType = "physical-access"
   TimeFormat = "epoch"
   Conditions = ["""CEF:""", """|C-CURE|""", """|Card"""]
   Fields = [
     """src=({host}[^\s]{1,2000})""",
     """({outcome}Card (Rejected|Admitted))""",
     """\|start=({time}\d{1,100})""",
     """\ssuid=(?:Unknown|(({domain}[^\\]{1,2000})\\?)?({user}.+?))\s(\w+=|$)""",
     """\ssuser=(?:|({user_fullname}.+?))\s(\w+=|$)""",
     """\scs1=(?:|({location_door}.+?))\s(\w+=|$)""",
     """\scs3=(?:|({location_city}.+?))\s(\w+=|$)"""
   ]
 }
```