#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-create-2
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Splunk
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """RT_FLOW: RT_FLOW_SESSION_CREATE""", """session created""" ]
    Fields = [
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """(\w+\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})\s({host}[^\s]+)\s({event_name}RT_FLOW: [^:]+)(?:[^\s]+\s){3}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({src_port}\d{1,100})->({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({dest_port}\d{1,100})\s((None)|(junos-)?({service}[^\s]+))\s(?:[^\s]+\s){5}((N\/A)|({protocol}[^\s]+))\s({policy}[^\s]+)\s((N\/A)|({src_network_zone}[^\s]+))\s((N\/A)|({dest_network_zone}[^\s]+))\s(\d{1,100}|\S+)\s{0,100}(\d{1,100})?\s{0,100}((N\/A)|({user}[^\s]+))\(\S+\)\s({src_interface}[^\s]+)\s((UNKNOWN)|({network_app}[^\s]+))\s((UNKNOWN)|({subtype}[^\s]+))\s((UNKNOWN)|({additional_info}[^\s]+))"""
    ]
}
```