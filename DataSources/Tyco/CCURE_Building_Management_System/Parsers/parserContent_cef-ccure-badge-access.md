#### Parser Content
```Java
{
Name = cef-ccure-badge-access
   Vendor = Tyco
   Product = CCURE Building Management System
   Lms = ArcSight
   DataType = "physical-access"
   TimeFormat = "epoch"
   Conditions = ["""CEF:""", """|CCURE|ACS|""", """flexNumber1="""]
   Fields = [
     """\sdvc=({host}[^\s]{1,2000})""",
     """\sdvchost=({host}[^\s]{1,2000})""",
     """(?:([^\|]{0,2000}\|)){5}({outcome}[^\|]{1,2000})"""
     """\srt=({time}\d{1,100})""",
     """\ssuser=(?:N\/A|({user}.+?))\s(\w+=|$)""",
     """\scs1=({first_name}.+?)\s(\w+=|$)""",
     """\scs2=({last_name}.+?)\s(\w+=|$)""",
     """\sflexNumber1=({badge_id}\d{1,100})""",
     """\scs4=({department}.+?)\s(\w+=|$)""",
     """\scs5=({company}.+?)\s(\w+=|$)""",
     """\smsg=({location_door}.+?)\s(\w+=|$)"""
   ]
 }
```