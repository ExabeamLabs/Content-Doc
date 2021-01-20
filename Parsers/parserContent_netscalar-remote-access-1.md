#### Parser Content
```Java
{
Name = netscalar-remote-access-1
 Product =Netscaler VPN
 Vendor =Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """ SSLVPN """ , """ HTTPREQUEST """ ]
 Fields =[
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s+({host}[\w.\-]+)(\s+\S+){3}\s+({log_type}SSLVPN HTTPREQUEST)?.*?Context\s*({user}[^@]+)@({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*-\s*.*?-\s*({dest_host}.*?)User.*?\s*Vserver\s*({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({dest_port}\d+).*?POST\s*({action}[^\s]+)""",
   """({event_name}HTTPREQUEST)"""
 ]
}
```