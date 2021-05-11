#### Parser Content
```Java
{
Name = sophos-security-alert-2
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::Application::Blocked"""", """"Controlled application blocked: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"location":"({host}[^"]+)""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({alert_name}[^:]+):\s({target}[^"]+)""",
    """"name":\s{0,100}"({additional_info}[^"]+)""",
    """"type":\s{0,100}"({alert_type}[^"]+)""",
    """"dhost":\s{0,100}"({src_host}[^"]+)""",
    """"severity":\s{0,100}"({alert_severity}[^"]+)""",
    """"suser":\s{0,100}"(?:n\/a|({user_fullname}[^"\\,]+))"""",
    """"suser":\s{0,100}"({user_lastname}[^",\s]+),\s{0,100}({user_firstname}[^,"\s]+)"""",
    """"suser":\s{0,100}"(({domain}[^\\",]+)\\+)?({user}[^",\\\/\s]+)"""",
    """"source":"({user_fullname}[^",]+)"""",
    """"source":"({user_lastname}[^",\s]+),\s{0,100}({user_firstname}[^,"\s]+)"""",
    """\\"source_info\\"__ip=({src_ip}[A-Fa-f:\d.]+)""",
    """"id":\s{0,100}"({alert_id}[^"]+)""",
  ]
  DupFields = [ "host->src_host" ]
}
```