#### Parser Content
```Java
{
Name = pensando-flow-create
    Vendor = AMD
    Product = Pensando
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSZ"
    Conditions = ["""pen-netagent""","""flow_create"""]
    Fields = [
       """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
       """\d{2}Z ({host}[\w.-]{1,2000}?) pen-netagent""",
       """({event_name}flow_create),({action}[^,]{1,2000}),({vrf}\d{1,200}),({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({src_port}\d{1,200}),({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),({dest_port}\d{1,200}),({protocol}\d{1,200}),({session_id}[^,]{1,2000}),({policy_id}[^,]{1,2000}?),({rule_id}\d{1,200}),({rule}[^,]{1,2000}?),({packets}\d{1,200}),({bytes_in}\d{1,200}),({rflow_packets}\d{1,200}),({bytes_out}\d{1,200}),({vlan_id}\d{1,200}),({device_type}[^,]{1,2000}),([^,]{0,2000}?,){2}({mac_address}[^,]{1,2000}?),"""
    ]  


}
```