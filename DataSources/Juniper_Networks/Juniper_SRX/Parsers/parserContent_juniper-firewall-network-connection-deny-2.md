#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-deny-2
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Splunk
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """RT_FLOW: RT_FLOW_SESSION_DENY""", """session denied""" ]
    Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
	"""(\w+\s\d+\s\d+:\d+:\d+)\s({host}[^\s]+)\s({event_name}RT_FLOW: [^:]+)(?:[^\s]+\s){3}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({src_port}\d+)->({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({dest_port}\d+)\s((None)|(junos-)?({service}[^\s]+))\s((N\/A)|({protocol_id}[^\s]+))\s((N\/A)|({policy}[^\s]+))\s((N\/A)|({src_network_zone}[^\s]+))\s((N\/A)|({dest_network_zone}[^\s]+))\s((UNKNOWN)|({network_app}[^\s]+))\s((UNKNOWN)|({subtype}[^\s]+))\s((N\/A)|({user}[^\s]+))\(\S+\)\s({src_interface}[^\s]+)\s((UNKNOWN)|({additional_info}[^\s]+))\s\S+\s({action}\S+)"""        
    ]
}
```