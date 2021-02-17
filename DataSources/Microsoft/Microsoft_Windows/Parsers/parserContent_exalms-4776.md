#### Parser Content
```Java
{
Name = exalms-4776
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4776"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":4776""", """The computer attempted to validate the credentials for an account.""", """"@timestamp"""" ]
  Fields = [
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """"@timestamp"\s*:\s*"({time}[^"]+)"""",
    """"(?:winlog\.)?computer_name"+\s*:\s*"+({host}[^"]+)"""",
    """"(?:winlog\.)?computer_name"+\s*:\s*"+[^\.]+\.({domain}[^"]+)""",
    """"event_id"\s*:\s*({event_code}\d+)""",
    """"event_data"\s*:\s*\{.*?"Workstation"\s*:\s*"(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)(\\*({dest_host}[^\s"]+))))"""",
    """"event_data"\s*:\s*\{.*?"Status"\s*:\s*"({result_code}[\w\-]+)"""",
    """"TargetUserName"\s*:\s*"(?![^\s"@]+@[^\s"@]+)({user}[^\s@"]+)"""",
    """"TargetUserName"\s*:\s*"(?=[^\s]+@[^\s]+)({user_email}({user}[^\s"@]+)@({domain}[^\s"@]+))"""",
    """"(record_number|record_id)"\s*:\s*"*({record_id}\d+)""",
  ]
}
```