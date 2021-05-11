#### Parser Content
```Java
{
Name = sophos-dlp-alert-1
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::Device::Blocked""", """"name": "Peripheral """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({alert_name}[^"':]+)""",
    """"name":\s{0,100}"({additional_info}[^"]+)""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
    """"dhost":\s{0,100}"({src_host}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"suser":\s{0,100}"(?:n\/a|({user_fullname}[^"\\]+))"""",
    """"suser":\s{0,100}"(?:n\/a|({user}[^",\\\s]+))"""",
    """"suser":\s{0,100}"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"id":\s{0,100}"({alert_id}[^"]+)""",
  ]
}
```