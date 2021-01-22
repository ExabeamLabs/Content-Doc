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
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s+({host}[\w.\-]+)(\s+\S+){3}\s+({log_type}SSLVPN HTTPREQUEST)?.*?Context\s*(({user_email}[^@]+@[^@]+)|({user}[^@]+))@({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+-\s*SessionId:\s+({session_id}[^\s]+)\s*-\s*({dest_host}.*?)\s+User.*?\s*Vserver\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d+).*?SSO[^:]+:\s*({method}[^\s]+)\s+({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?\s+""",
   """({event_name}HTTPREQUEST)"""
 ]
}
```