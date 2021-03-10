#### Parser Content
```Java
{
Name = squid-web-activity
  Vendor = Squid
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """squid-access-default:""" ]
  Fields = [
    """({host}\S+)\s+squid-access-default:\s+({time}\d{10}\.\d{3})\s+({duration}\d+)\s+({src_ip}[a-fA-F\d.:]+)\s+(?:\w+\/)({result_code}\d+)\s+({bytes_out}\d+)\s+({method}\S+)\s+(?:\w+\:\/+)?(?:({dest_host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\s:\/]+))(?:\:({dest_port}\d+))?\S*?\s+({user}\S+)\s+({hierarchy_code}[^\/]+)\/({forwarded_host}[^\/\s]+)\s""",
    """squid-access-default:(\s+\S+){6}\s+.*?({top_domain}[^.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(?:\:\d+)?\s+"""
  ]
}
```