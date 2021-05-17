#### Parser Content
```Java
{
Name = netscalar-remote-access-1
 Vendor = Citrix
 Product = Citrix Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """ SSLVPN """ , """ HTTPREQUEST """ ]
 Fields =[
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s{1,100}({host}[\w.\-]{1,2000})(\s{1,100}\S+){3}\s{1,100}({log_type}SSLVPN HTTPREQUEST)?.*?Context\s{0,100}(({user_email}[^@]{1,2000}@[^@]{1,2000})|({user}[^@]{1,2000}))@({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{1,100}-\s{0,100}SessionId:\s{1,100}({session_id}[^\s]{1,2000})\s{0,100}-\s{0,100}({dest_host}.*?)\s{1,100}User.*?\s{0,100}Vserver\s{0,100}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100}).*?SSO[^:]{1,2000}:\s{0,100}({method}[^\s]{1,2000})\s{1,100}({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?\s{1,100}""",
   """({event_name}HTTPREQUEST)"""
 ]
}
```