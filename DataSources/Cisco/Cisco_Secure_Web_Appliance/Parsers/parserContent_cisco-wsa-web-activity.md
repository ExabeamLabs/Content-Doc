#### Parser Content
```Java
{
Name = cisco-wsa-web-activity
  Vendor = Cisco
  Product = Cisco Secure Web Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ SOC_ExabeamPOC_accesslogs: Info: """ ]
  Fields = [
	"""\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]+)\s{1,100}SOC_ExabeamPOC_accesslogs: Info:\s{0,100}({time}\d{10})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}(NONE|({proxy_action}[^\s\/]+))\/({result_code}\d{1,100})\s{1,100}\d{1,100}\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?]*)?({uri_query}\?[^\s]*?)?)),?\s{1,100}(\S+\s{1,100}\S+\s{1,100}(-|({mime}\S+))\s{1,100}.+?<(-|({category}[^,">]+)))?""",
	"""({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^:\/\.\s]+(?i)(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|aero|ai|be|cloud|goog|gt|im|ki|la|market|marketing|mobi|ms|network|ninja|page|pub|report|services|tg|uy))+(\/|:))[^\s\/:]+)"""
  ]
  DupFields = ["dest_ip->web_domain"]
}
```