#### Parser Content
```Java
{
Name = sophos-security-alert-2
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::Application::Blocked"""", """"Controlled application blocked: """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[^"]{1,2000})""",
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"rt":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":\s{0,100}"({alert_name}[^:]{1,2000}):\s({target}[^"]{1,2000})""",
    """"name":\s{0,100}"({additional_info}[^"]{1,2000})""",
    """"type":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """"suser":\s{0,100}"(?:n\/a|({user_fullname}[^"\\,]{1,2000}))"""",
    """"suser":\s{0,100}"({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000})"""",
    """"suser":\s{0,100}"(({domain}[^\\",]{1,2000})\\+)?({user}[^",\\\/\s]{1,2000})"""",
    """"source":"({user_fullname}[^",]{1,2000})"""",
    """"source":"({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000})"""",
    """\\"source_info\\"__ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})""",
  ]
  DupFields = [ "host->src_host" ]


}
```