#### Parser Content
```Java
{
Name = squid-web-activity-1
  Vendor = Squid
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """<squid-web-activity-1>""" ]
  Fields = [
    """({time}\d{10})\.\d{3}\s+({duration}\S+)\s+({src_ip}\S+)\s+({proxy_action}[^\s\/]+)\/({result_code}\d+)\s+({bytes_out}\d+)\s+({method}\S+)\s+({full_url}(\w+:\/+)?({web_domain}[^\s\/]+?)(:\d+|\/\S*?))\s+(?:-|({user}\S+))\s+({hierarchy_code}[^\s\/]+)\/(?:-|({forwarded_host}\S+))\s+(?:-|({mime}\S+))""",
    """\d{10}\.\d{3}(\s+\S+){5}\s+(({protocol}\w+):\/+)?[^\s\/]*?({uri_path}\/[^\s\?]*?)({uri_query}\?[^\s]+)?\s""",
    """\d{10}\.\d{3}(\s+\S+){5}\s+(\w+:\/+)?[^\s\/]*?({top_domain}[^\s\.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(:|\/|\s)""",
  ]
}
```