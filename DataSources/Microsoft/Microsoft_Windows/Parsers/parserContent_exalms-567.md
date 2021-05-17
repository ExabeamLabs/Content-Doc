#### Parser Content
```Java
{
Name = exalms-567
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-567"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":567,""", "Object Access Attempt:" ,""""@timestamp"""" ]
  Fields = [
    """({event_name}Object Access Attempt)""",
    """"@timestamp"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})""",
    """({event_code}567)""",
    """"user"\s{0,100}:\s{0,100}\{[^\}]{0,2000}"identifier"\s{0,100}:\s{0,100}"({user_sid}[^"]{1,2000})""",
    """"user"\s{0,100}:\s{0,100}\{[^\}]{0,2000}"name"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})""",
    """"user"\s{0,100}:\s{0,100}\{[^\}]{0,2000}"domain"\s{0,100}:\s{0,100}"({domain}[^"]{1,2000})""",
    """"(param3|ObjectType)"\s{0,100}:\s{0,100}"({file_type}[^"]{1,2000})""",
    """"(param5|ObjectName)"\s{0,100}:\s{0,100}"({file_path}[^"]{1,2000})""",
    """"(param5|ObjectName)"\s{0,100}:\s{0,100}"([^"]{0,2000}\\)?({file_name}[^\\\."]{1,2000}(\.({file_ext}[^\.\\"]{1,2000}))?)"""",
    """"(param5|ObjectName)"\s{0,100}:\s{0,100}"({file_parent}.+?)\\+[^\\]{1,2000}"""",
    """"(param6|Accesses)"\s{0,100}:\s{0,100}"({accesses}.+?)"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```