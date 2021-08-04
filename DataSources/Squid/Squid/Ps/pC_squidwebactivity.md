#### Parser Content
```Java
{
Name = squid-web-activity
  Vendor = Squid
  Product = Squid
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """squid-access-default:""" ]
  Fields = [
    """({host}\S+)\s{1,100}squid-access-default:\s{1,100}({time}\d{10}\.\d{3})\s{1,100}({duration}\d{1,100})\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}(?:\w+\/)({result_code}\d{1,100})\s{1,100}({bytes_out}\d{1,100})\s{1,100}({method}\S+)\s{1,100}(?:\w+\:\/+)?(?:({dest_host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\s:\/]{1,2000}))(?:\:({dest_port}\d{1,100}))?\S*?\s{1,100}({user}\S+)\s{1,100}({hierarchy_code}[^\/]{1,2000})\/({forwarded_host}[^\/\s]{1,2000})\s""",
    """squid-access-default:(\s{1,100}\S+){6}\s{1,100}.*?({top_domain}[^.]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(?:\:\d{1,100})?\s{1,100}"""
  ]
}
```