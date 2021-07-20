#### Parser Content
```Java
{
Name = s-stream-dhcp
  Vendor = Splunk Stream
  Product = Splunk Stream
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"opcode":"""", """ip:udp:dhcp""", """"giaddr":"""", """"flow_id":"""" ]
  Fields = [
    """"timestamp":"({time}[^"]{1,2000})"""",
    """"bytes":({bytes}[^,]{1,2000}),""",
    """"bytes_in":({bytes_in}[^,]{1,2000}),""",
    """"bytes_out":({bytes_out}[^,]{1,2000}),""",
    """"dest_ip":"({dest_ip}[^"]{1,2000})"""",
    """"dest_mac":"({dest_mac}[^"]{1,2000})"""",
    """"dest_port":({dest_port}[^,]{1,2000}),""",
    """"dns_server":\[({dns_ip_flow}[^\]]{1,2000})\]""",
    """"domain_name":\[({domain}[^\]]{1,2000})\]""",
    """"opcode":"({event_name}[^"]{1,2000})"""",
    """"router":\[({router_ip_flow}[^\]]{1,2000})\]""",
    """"src_ip":"({src_ip}[^"]{1,2000})"""",
    """"src_mac":"({src_mac}[^"]{1,2000})"""",
    """"src_port":({src_port}[^,]{1,2000}),""",
    """"subnetmask":"({router_subnet}[^"]{1,2000})"""",
    """"transaction_id":({trans_id}[^,]{1,2000}),""",
    """({protocol}dhcp)""",
    """"yiaddr":"({assigned_ip}[^"]{1,2000})"""",
    """"ip_lease_time":({ip_lease_time}\d{1,100}),""",
    """"host_name":"({host}[^"]{1,2000})"""",
  ]
}
```