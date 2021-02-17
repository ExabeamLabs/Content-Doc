#### Parser Content
```Java
{
Name = netscalar-remote-access
 Vendor = Citrix
 Product = Citrix Netscaler VPN
 Lms = Direct
 TimeFormat = "MM/dd/yyyy:HH:mm:ss"
 DataType = "remote-access"
 Conditions = [ """ After Initialization """ ]
 Fields =[
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s+({host}[\w.\-]+)(\s+\S+){3}\s+({log_type}SSLVPN Message)?\s.*?user\s*({user}[^\s]+)\s*clientip\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*(request:\s*({action}[^\s]+))?""",
   """SSO\s+({event_name}[^:]+): After Initialization user ({user}.+?)\s+clientip\s+(127.0.0.1|({src_ip}[^\s]+))\s"""
  """({event_name}ns_sslvpn_process_sso_conn)""" 
 ]
}
```