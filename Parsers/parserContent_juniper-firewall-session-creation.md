#### Parser Content
```Java
{
Name = juniper-firewall-session-creation 
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss Z"
  Conditions = [ """RT_FLOW_SESSION_CREATE: session created""", """ testbed-untrust """, """ testbed-trust """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \+\d\d:\d\d)\s+RT_FLOW_SESSION_CREATE:\s+({event_name}session created)\s+({src_ip}[\da-fA-F.:]+)\/({src_port}\d+)->({dest_ip}[\da-fA-F.:]+)\/({dest_port}\d+)\s+(None|junos-({protocol}[^\s]+))\s+({src_translated_ip}[\da-fA-F.:]+)\/({src_translated_port}\d+)->({dest_translated_ip}[\da-fA-F.:]+)\/({dest_translated_port}\d+)\s+({rule}[^\s]+\srule)(\s+\S+){4}\s({policy}[^\s]+)(\s+\S+){4}\s+({src_interface}[^\s]+)""",    
  ]  
}
```