#### Parser Content
```Java
{
Name = ibm-web-activity
  Vendor = IBM
  Product = IBM Security Access Manager
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""webseald""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)-\d\d:\d\d\s({host}[^\s]+)\s""",
    """webseald\s\d{1,100}\s(.*?\s){4}(-|({user}[^\s]+))""",
    """"({request}({method}[^\s]+)\sHTTPS*:\/\/({full_url}[^\s]+\.({top_domain}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ca))[^\s]+))\s({protocol}[^\/]+).*?"\s({result_code}\d{1,100})\s(-|\d{1,100})\s.*?\s(-|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))"""
  ]
}
```