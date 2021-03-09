#### Parser Content
```Java
{
Name = eset-domain-user-login
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    DataType = "authentication-successful"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """|Domain user login|""" ]
    Fields = [
      """\Wcat=({category}[^=]+?)\s*(\w+=|$)""",
      """\Wsev=({alert_severity}\d+)""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """\Waction=({activity}[^\s]+)\s""",
      """\Wresult=({outcome}[^=]+?)\s*(\w+=|$)""",
      """\WdeviceName=({host}[^\s]+)\s""",
      """\Wtarget=({object}[^\s]+)\s*""",
      """\Wdetail=({additional_info}[^.]+).""",
      """\Wuser '\w+\\({user}[^\s]+)'.""",
      """(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\|({event_name}[^|]+)\|""",
      """({service}RemoteAdministrator)""", 
      """\d+Z\s*({host}\w+)\s""",
    ]
  }
```