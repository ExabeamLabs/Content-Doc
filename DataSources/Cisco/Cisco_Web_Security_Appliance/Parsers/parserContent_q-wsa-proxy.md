#### Parser Content
```Java
{
Name = q-wsa-proxy
  Vendor = Cisco
  Product = Cisco Web Security Appliance
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ QRadarLogging: Info: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Info:\s*({time}\d+)\.\d+\s+\d+\s+({src_ip}[A-Fa-f:\d.]+)\s+(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d+)\s+({bytes_out}\d+)\s+({method}\S+)\s+(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?({web_domain}[^\\\/\s:,"]+)(:\d+)?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))(\s+(-|"+(({domain}[^\\\s"]+)\\+)?({user_email}({user}[^\\\s"@]+)@[^\\\s"@]+)"+)\s+[^\s\/]+\/+(-|({=web_domain}[^\s\/]+))\s+(-|({mime}\S+))\s+.+?<(-|({category}[^",>]+)).+?dst\s+(-|({dest_ip}[A-Fa-f:\d.]+))\s+dstPort\s+({dest_port}\d+))?""",
    """({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|im|technology))+)(:|\/)"""
  ]
}
```