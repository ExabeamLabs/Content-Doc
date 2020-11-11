#### Parser Content
```Java
{
Name = s-skysea-web-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,Web????????????,""" ]
  Fields = [
    """({host}[\w\-.]+),\d+,({src_host}[\w\-.]+),({src_ip}[A-Fa-f:\d.]+),[^,]*,({user}[^\s,]+),({user_fullname}[^,\(\???]+(\???[^\???,]+\???)?)({department}[^,]+)[^,]*,({time}\d+\/\d+\/\d+ \d+:\d+:\d+),Web????????????,([^,]*,){2}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d+)?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s,]*)?)),([^,]*,){5}({action}[^,]+)""",
    """,Web????????????,([^,]*,){2}[^\s,"]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
  ]
}
```