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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}[^"]+)"""",
    """"(?:winlog\.)?computer_name"{1,20}\s{0,100}:\s{0,100}"{1,20}({host}[^"]+)"""",
    """"(?:winlog\.)?computer_name"{1,20}\s{0,100}:\s{0,100}"{1,20}[^\.]+\.({domain}[^"]+)""",
    """"event_id"\s{0,100}:\s{0,100}({event_code}\d{1,100})""",
    """"event_data"\s{0,100}:\s{0,100}\{.*?"Workstation"\s{0,100}:\s{0,100}"(({dest_ip}[A-Fa-f:\d.]+)|(?:(?!NULL)(\\*({dest_host}[^\s"]+))))"""",
    """"event_data"\s{0,100}:\s{0,100}\{.*?"Status"\s{0,100}:\s{0,100}"({result_code}[\w\-]+)"""",
    """"TargetUserName"\s{0,100}:\s{0,100}"(?![^\s"@]+@[^\s"@]+)({user}[^\s@"]+)"""",
    """"TargetUserName"\s{0,100}:\s{0,100}"(?=[^\s]+@[^\s]+)({user_email}({user}[^\s"@]+)@({domain}[^\s"@]+))"""",
    """"(record_number|record_id)"\s{0,100}:\s{0,100}"{0,20}({record_id}\d{1,100})""",
  ]
}
```