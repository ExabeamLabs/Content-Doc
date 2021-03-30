#### Parser Content
```Java
{
Name = cef-paloalto-firewall
   Vendor = Palo Alto Networks
   Product = NGFW
   Lms = Direct
   DataType = "network-connection"
   IsHVF = true
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
   Conditions = ["""|McAfee|ESM|""" , """PANOS TRAFFIC"""]
   Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).""",
     """PANOS\sTRAFFIC\s({activity}.+?)\|"""
     """proto=({protocol}[^\s].+?)\s""",
     """src=({src_ip}[^\s]*)\s""",
     """dst=({dest_ip}[^\s]*)\s""",
     """spt=({src_port}[^\s]*)\s""",
     """dpt=({dest_port}[^\s]*)\s""",
     """nitroInterface_Dest=({dest_interface}[^\s]*)\s""",
     """nitroInterface=({src_interface}[^\s]*)\s""",
     """suser=({user}.+?)\s""",
     """cat=({object}.+?)\snitro"""
   ]
}
```