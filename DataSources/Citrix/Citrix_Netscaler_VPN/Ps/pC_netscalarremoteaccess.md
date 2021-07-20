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
   """({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d \w+)\s{1,100}({host}[\w.\-]{1,2000})(\s{1,100}\S+){3}\s{1,100}({log_type}SSLVPN Message)?\s.*?user\s{0,100}({user}[^\s]{1,2000})\s{0,100}clientip\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{0,100}(request:\s{0,100}({action}[^\s]{1,2000}))?""",
   """SSO\s{1,100}({event_name}[^:]{1,2000}): After Initialization user ({user}.+?)\s{1,100}clientip\s{1,100}(127.0.0.1|({src_ip}[^\s]{1,2000}))\s"""
  """({event_name}ns_sslvpn_process_sso_conn)""" 
 ]
}
```