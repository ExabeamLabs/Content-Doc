#### Parser Content
```Java
{
Name = q-wsa-proxy
  Vendor = Cisco
  Product = Cisco Secure Web Appliance
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """QRadarLogging: Info:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Info:\s{0,100}({time}\d{1,100})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d{1,100})\s{1,100}({bytes_out}\d{1,100})\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d{1,100})?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))\s(-|({domain}[^s]+))\s.*?\s({mime}[^\s]+)""",
    """Info:\s{0,100}({time}\d{1,100})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d{1,100})\s{1,100}({bytes_out}\d{1,100})\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d{1,100})?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))(\s{1,100}(-|"{1,20}(({domain}[^\\\s"]+)\\+)?({user_email}({user}[^\\\s"@]+)@[^\\\s"@]+)"{1,20})\s{1,100}[^\s\/]+\/+(-|({=web_domain}[^\s\/]+))\s{1,100}(-|({mime}\S+))\s{1,100}.+?<(-|({category}[^",>]+)).+?dst\s{1,100}(-|({dest_ip}[A-Fa-f:\d.]+))\s{1,100}dstPort\s{1,100}({dest_port}\d{1,100}))?""",
    """Info:\s.*?\s({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})\s({proxy_action}[^\/]+)\/({result_code}\d{1,100})\s\d{1,100}\s({method}[^\s]+)({full_url}.+?\.({top_domain}[^\s]*\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))[^\s]+)""",
    """"(-|({category}[^"]+?))",([^,]+?,){19}->""",
    """dst\s(-|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\sdstPort\s(-|({dest_port}\d{1,100}))"""
  ]
}
```