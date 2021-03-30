#### Parser Content
```Java
{
Name = asa-web-activity-716003
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%ASA-""", """-716003""", """WebVPN access GRANTED""" ]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d) ({host}[\w\-.]+) : %ASA-\d+-({event_code}\d+): .+? User <({user_email}[^>]+)> IP <({src_ip}[A-Fa-f:\d.]+)> ({event_name}WebVPN access ({action}[^:]+)):\s*(-|({full_url}({protocol}[^:\\\/]+):[\\\/]+({web_domain}[^\\\/:]+)({uri_path}\/[^\s\?]*)?({uri_query}\?[^\s]+)?))""",
    """WebVPN access GRANTED:\s*.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
   ]
}
```