#### Parser Content
```Java
{
Name = cef-paloalto-firewall-global-protect
   Vendor = Palo Alto Networks
   Product = GlobalProtect
   Lms = Direct
   DataType = "config-change"
   IsHVF = true
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
   Conditions = ["""|McAfee|ESM|""" , """PANOS SYSTEM"""]
   Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).""",
     """Protect\sPortal\s({activity}.+?)\|"""
     """src=({src_ip}[^\s]{0,2000})\s""",
     """suser=({user}.+?)\s""",
     """cat=({object}.+?)\snitro"""
   ]
}
```