#### Parser Content
```Java
{
Name = squid-web-activity-5
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  TimeFormat ="dd/MMM/yyyy:HH:mm:ss +SSSS"
  Conditions = [ """] SquidProxy """ ]
  Fields = [
    """(-|({host}[a-fA-F\d:\.]{1,2000}))\s\S+\s\S+\s\[({time}\d\d\/\w{3}\/\d\d\d\d:\d\d:\d\d:\d\d\s[+-]\d{4})\]\sSquidProxy""",
    """SquidProxy\s\S+\s({src_ip}[a-fA-F\d:\.]{1,2000})""",
    """SquidProxy\s(\S+\s){2}"({method}[^\s]{1,2000})\s""",
    """SquidProxy\s(\S+\s){2}"\S+\s\S+\s({protocol}[^"\/]{1,2000})""",
    """SquidProxy\s(\S+\s){2}"[^"]{1,2000}"\s({result_code}\d{1,3})\s""",
    """SquidProxy\s(\S+\s){2}"[^"]{1,2000}"\s\d{1,3}\s({bytes}\d{1,20})\s(NONE_NONE|({proxy_action}[^:]{1,2000})):""",
    """SquidProxy\s(\S+\s){2}"\S+\s(http:\/\/)?({web_domain}[^\s\/"]{1,2000}?)?(:({dest_port}\d{1,5}))?({uri_path}\/[^"\s\?]{0,2000})?({uri_query}\?[^"\s]{1,2000})?\s"""
  ]


}
```