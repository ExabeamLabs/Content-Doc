#### Parser Content
```Java
{
Name = cisco-wsa-web-activity-2
  Vendor = Cisco
  Product = Cisco Web Security Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ Info: """ , """ TCP_"""]
  Fields = [
        """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+\w+: Info:\s*({time}\d{10})\.\d+\s+\d+\s+({src_ip}[A-Fa-f:\d.]+)\s+""",
        """({proxy_action}TCP[^\s\/]+)\/({result_code}\d+)\s+\d+\s+({method}\S+)\s+(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?]*)?({uri_query}\?[^\s]*?)?)),?\s+""",
        """({top_domain}(?!(?:\d+\.){3}\d+)[^:\/\.\s]+(?i)(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|aero|ai|be|cloud|goog|gt|im|ki|la|market|marketing|mobi|ms|network|ninja|page|pub|report|services|tg|uy))+(\/|:| -))[^\s\/:]+)"""
        """"({domain}[^\\]+)\\({user_email}[^@]+@[^"]+)"\s\w+\/""",
        """\s<(.+?,){22}"+({category}[^"]+)"""
  ]
  DupFields = ["dest_ip->web_domain"]
}
```