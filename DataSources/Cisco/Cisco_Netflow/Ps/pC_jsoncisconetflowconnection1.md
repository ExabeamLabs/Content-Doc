#### Parser Content
```Java
{
Name = json-cisco-netflow-connection-1
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "epoch"
  Conditions = [ """"nexthop":"""", """"sys_uptime":""", """"first":""", """"tcp_flags":""", """"unix_secs":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"sys_uptime":({time}\d{1,100})""",
    """"srcaddr":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"dstaddr":"({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """"dPkts":({packets}\d{1,100})""",
    """"first":({flow_start_time}\d{1,100})""",
    """"last":({flow_end_time}\d{1,100})""",
    """"srcport":({src_port}\d{1,100})""",
    """"dstport":({dest_port}\d{1,100})""",
    """"tcp_flags":({tcp_flags}\d{1,100})""",
    """"prot":({protocol}\d{1,100})"""
  ]


}
```