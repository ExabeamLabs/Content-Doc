#### Parser Content
```Java
{
Name = exalms-680
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-680"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":680""", """"Logon attempt by:""", """"@timestamp"""" ]
  Fields = [
    """({event_name}Logon attempt)""",
    """"@timestamp"\s{0,100}:\s{0,100}"({time}[^"]+)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}[\w\-\.]+)"""",
    """"event_data"\s{0,100}:\s{0,100}\{.*?"(param3|SourceWorkstation)"\s{0,100}:\s{0,100}"({dest_host}[^"]+)"""",
    """"event_data"\s{0,100}:\s{0,100}\{.*?"(param4|ErrorCode)"\s{0,100}:\s{0,100}"({result_code}[^"]+)"""",
    """"event_data"\s{0,100}:\s{0,100}\{.*?"(param2|UserName|User)"\s{0,100}:\s{0,100}"({user}[^"]+)"""",
    """"hostname":"({domain}[^"]+)"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"identifier"\s{0,100}:\s{0,100}"({user_sid}[^"]+)"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"domain":"({domain}[^"]+)"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"name":"({user}[^"]+)"""",
    """"event_id"\s{0,100}:\s{0,100}({event_code}\d{1,100})""",
    """"record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})""",
  ]
}
```