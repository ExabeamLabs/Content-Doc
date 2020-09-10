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
    """"timestamp":"({time}[^"]+)"""",
    """"bytes":({bytes}[^,]+),""",
    """"bytes_in":({bytes_in}[^,]+),""",
    """"bytes_out":({bytes_out}[^,]+),""",
    """"dest_ip":"({dest_ip}[^"]+)"""",
    """"dest_mac":"({dest_mac}[^"]+)"""",
    """"dest_port":({dest_port}[^,]+),""",
    """"dns_server":\[({dns_ip_flow}[^\]]+)\]""",
    """"domain_name":\[({domain}[^\]]+)\]""",
    """"opcode":"({event_name}[^"]+)"""",
    """"router":\[({router_ip_flow}[^\]]+)\]""",
    """"src_ip":"({src_ip}[^"]+)"""",
    """"src_mac":"({src_mac}[^"]+)"""",
    """"src_port":({src_port}[^,]+),""",
    """"subnetmask":"({router_subnet}[^"]+)"""",
    """"transaction_id":({trans_id}[^,]+),""",
    """({protocol}dhcp)""",
    """"yiaddr":"({assigned_ip}[^"]+)"""",
    """"ip_lease_time":({ip_lease_time}\d+),""",
    """"host_name":"({host}[^"]+)"""",
  ]
}
```