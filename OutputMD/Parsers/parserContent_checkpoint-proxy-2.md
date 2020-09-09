#### Parser Content
```Java
{
Name = checkpoint-proxy-2
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """product:\"URL Filtering\"""", """src_user_name:\"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+({host}[\w.\-]+)\s+CheckPoint\s""",
    """action:\\"({action}[^"\\]+)""",
    """src:\\"({src_ip}[^"\\]+)""",
    """dst:\\"({dest_ip}[^"\\]+)""",
    """resource:\\"({additional_info}[^"]+?)\\"""",
    """url=({full_url}(\w+://)?({web_domain}[^"\/:;]+)({uri_path}/[^"\?;]*?)({uri_query}\?[^";]*?)?)(\\"|;)""",
    """s_port:\\"({src_port}[^"\\]+)""",
    """src_machine_name:\\"({host}[^"\\@]+)(@({domain}\w+)?)""",
    """src_user_name:\\"({user_fullname}[^"\\\(]+?)\s*(\(|\\)""",
    """resource:\\"[^"\\]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s"\\]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\\|/)"""
  ]
}
```