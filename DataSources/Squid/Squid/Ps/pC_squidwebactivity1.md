#### Parser Content
```Java
{
Name = squid-web-activity-1
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """<squid-web-activity-1>""" ]
  Fields = [
    """({time}\d{10})\.\d{3}\s{1,100}({duration}\S+)\s{1,100}({src_ip}\S+)\s{1,100}({proxy_action}[^\s\/]{1,2000})\/({result_code}\d{1,100})\s{1,100}({bytes_out}\d{1,100})\s{1,100}({method}\S+)\s{1,100}({full_url}(\w+:\/+)?({web_domain}[^\s\/]{1,2000}?)(:\d{1,100}|\/\S*?))\s{1,100}(?:-|({user}\S+))\s{1,100}({hierarchy_code}[^\s\/]{1,2000})\/(?:-|({forwarded_host}\S+))\s{1,100}(?:-|({mime}\S+))""",
    """\d{10}\.\d{3}(\s{1,100}\S+){5}\s{1,100}(({protocol}\w+):\/+)?[^\s\/]{0,2000}?({uri_path}\/[^\s\?]{0,2000}?)({uri_query}\?[^\s]{1,2000})?\s""",
  ]


}
```