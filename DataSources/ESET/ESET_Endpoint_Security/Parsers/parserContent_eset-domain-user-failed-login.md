#### Parser Content
```Java
{
Name = eset-domain-user-failed-login
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = Splunk
    DataType = "authentication-failed"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""", """cat=ESET RA Audit Event""", """|Failed domain user login|""" ]
    Fields = [
      """\Wcat=({category}[^=]+?)\s*(\w+=|$)""",
      """\Wsev=({alert_severity}\d+)""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
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