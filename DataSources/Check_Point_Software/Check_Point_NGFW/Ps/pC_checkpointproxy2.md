#### Parser Content
```Java
{
Name = checkpoint-proxy-2
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """product:\"URL Filtering\"""", """src_user_name:\"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}CheckPoint\s""",
    """action:\\"({action}[^"\\]{1,2000})""",
    """src:\\"({src_ip}[^"\\]{1,2000})""",
    """dst:\\"({dest_ip}[^"\\]{1,2000})""",
    """resource:\\"({additional_info}[^"]{1,2000}?)\\"""",
    """url=({full_url}(\w+://)?({web_domain}[^"\/:;]{1,2000})({uri_path}/[^"\?;]{0,2000}?)({uri_query}\?[^";]{0,2000}?)?)(\\"|;)""",
    """s_port:\\"({src_port}[^"\\]{1,2000})""",
    """src_machine_name:\\"({host}[^"\\@]{1,2000})(@({domain}\w+)?)""",
    """src_user_name:\\"({user_fullname}[^"\\\(]{1,2000}?)\s{0,100}(\(|\\)""",
  ]


}
```