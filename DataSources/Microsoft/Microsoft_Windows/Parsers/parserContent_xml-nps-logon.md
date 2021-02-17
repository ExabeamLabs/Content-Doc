#### Parser Content
```Java
{
Name = xml-nps-logon
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>627""", """Network Policy Server"""]
  Fields = [
     """<Computer>({host}[^<]+)<"""
     """SystemTime=\'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""" 
     """<EventID>({event_code}[^<]+)<\/EventID>""",
     """Account Name:\s*({user}[^\s]+)(\/?)""",
     """Account Name:\s*({user_type}.+?)(\/?)({user}[^\s\/.]+)\..+\s*Account Domain""",
     """Account Domain:\s*({domain}[^\s]+)\s*""",
     """Connection Request Policy Name:\s*({policy}.+?)\s*Network Policy""",
     """User:\s*Security ID:\s*({user_sid}.+?)\s*Account Name:""",
     """({event_name}Network Policy Server\s({outcome}\w+)\s.+?)\s*User:""",
     """Reason:\s*({failure_reason}[^<]+)\.\s""",
     """NAS IPv4 Address:\s*({dest_ip}[^\s-]+)\s""",
     """NAS IPv6 Address:\s*({dest_ip}[^\s-]+)\s""",
     """NAS Identifier:\s*({location}[^\s]]+)\s"""
  ]
}
```