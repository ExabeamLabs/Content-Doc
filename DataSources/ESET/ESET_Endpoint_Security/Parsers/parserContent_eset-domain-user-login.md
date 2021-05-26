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
      """\Wcat=({category}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wsev=({alert_severity}\d{1,100})""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """\Waction=({activity}[^\s]{1,2000})\s""",
      """\Wresult=({outcome}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\WdeviceName=({host}[^\s]{1,2000})\s""",
      """\Wtarget=({object}[^\s]{1,2000})\s{0,100}""",
      """\Wdetail=({additional_info}[^.]{1,2000}).""",
      """\Wuser '\w+\\({user}[^\s]{1,2000})'.""",
      """(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\|({event_name}[^|]{1,2000})\|""",
      """({service}RemoteAdministrator)""", 
      """\d{1,100}Z\s{0,100}({host}\w+)\s""",
    ]
  }
```