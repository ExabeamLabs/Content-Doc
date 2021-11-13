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
	"""\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}SOC_ExabeamPOC_accesslogs: Info:\s{0,100}({time}\d{10})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}(NONE|({proxy_action}[^\s\/]{1,2000}))\/({result_code}\d{1,100})\s{1,100}\d{1,100}\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?]{0,2000})?({uri_query}\?[^\s]{0,2000}?)?)),?\s{1,100}(\S+\s{1,100}\S+\s{1,100}(-|({mime}\S+))\s{1,100}.+?<(-|({category}[^,">]{1,2000})))?""",
  ]
  DupFields = ["dest_ip->web_domain"]


}
```