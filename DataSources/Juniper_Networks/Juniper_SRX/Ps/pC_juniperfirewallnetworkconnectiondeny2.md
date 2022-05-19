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
	"""(\w+\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})\s({host}[^\s]{1,2000})\s({event_name}RT_FLOW: [^:]{1,2000})(?:[^\s]{1,2000}\s){3}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({src_port}\d{1,100})->({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({dest_port}\d{1,100})\s((None)|(junos-)?({service}[^\s]{1,2000}))\s((N\/A)|({protocol_id}[^\s]{1,2000}))\s((N\/A)|({policy}[^\s]{1,2000}))\s((N\/A)|({src_network_zone}[^\s]{1,2000}))\s((N\/A)|({dest_network_zone}[^\s]{1,2000}))\s((UNKNOWN)|({network_app}[^\s]{1,2000}))\s((UNKNOWN)|({subtype}[^\s]{1,2000}))\s((N\/A)|({user}[^\s]{1,2000}))\(\S+\)\s({src_interface}[^\s]{1,2000})\s((UNKNOWN)|({additional_info}[^\s]{1,2000}))\s\S+\s({action}\S+)"""        
    ]


}
```