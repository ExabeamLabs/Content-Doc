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
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s{1,100}({host}[\w.\-]+)(\s{1,100}\S+){3}\s{1,100}({log_type}SSLVPN HTTPREQUEST)?.*?Context\s{0,100}(({user_email}[^@]+@[^@]+)|({user}[^@]+))@({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{1,100}-\s{0,100}SessionId:\s{1,100}({session_id}[^\s]+)\s{0,100}-\s{0,100}({dest_host}.*?)\s{1,100}User.*?\s{0,100}Vserver\s{0,100}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d{1,100}).*?SSO[^:]+:\s{0,100}({method}[^\s]+)\s{1,100}({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s{1,100}""",
   """({event_name}HTTPREQUEST)"""
 ]
}
```