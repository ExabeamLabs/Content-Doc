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
     """Account Name:\s{0,100}({user}[^\s]+)(\/?)""",
     """Account Domain:\s{0,100}({domain}[^\s]+)\s{0,100}""",
     """Account Name:\s{0,100}({user_type}[^\s:]+?)\/({user}[^\.\s\/:]+?)(\.[^:\.\s]+?)*\s{0,100}Account Domain""",
     """Connection Request Policy Name:\s{0,100}({policy}.+?)\s{0,100}Network Policy""",
     """User:\s{0,100}Security ID:\s{0,100}({user_sid}.+?)\s{0,100}Account Name:""",
     """({event_name}Network Policy Server\s({outcome}\w+)\s.+?)\s{0,100}User:""",
     """Reason:\s{0,100}({failure_reason}[^<]+)\.\s""",
     """NAS IPv4 Address:\s{0,100}({dest_ip}[^\s-]+)\s""",
     """NAS IPv6 Address:\s{0,100}({dest_ip}[^\s-]+)\s""",
     """NAS Identifier:\s{0,100}({location}[^\s]]+)\s"""
  ]
}
```