#### Parser Content
```Java
{
Name = barracuda-firewall-network-connection
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """/box_Firewall_Activity:  """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\/box_Firewall_Activity:\s{1,100}[^\s]+\s{1,100}({host}[^\s]+)\s{1,100}({activity}[^\s:]+):\s{1,100}""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}({event_code}[^\|\s]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}[^\|]*\|({protocol}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){2}({src_interface}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){3}(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){4}({src_port}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){5}({src_mac}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){6}(?:0.0.0.0|({dest_external_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){7}({dest_port}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){8}({app_protocol}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){9}({dest_interface}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){10}({rule}[^\|]+)\|""",
    """\s{1,100}(Allow|Remove|LocalRemove|LocalAllow):\s{1,100}([^\|]*\|){11}({outcome}[^\|]+)\|""",
    """\s{1,100}(Drop|Block|LocalBlock):\s{1,100}([^\|]*\|){11}({failure_reason}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){12}(?:0.0.0.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){13}(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){14}({duration}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){16}({bytes_in}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){17}({bytes_out}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]+\s{1,100}){3}([^\|]*\|){20}({user}[^\|]+)\|"""
  ]
}
```