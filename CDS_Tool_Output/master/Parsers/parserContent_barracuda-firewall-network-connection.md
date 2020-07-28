#### Parser Content
```Java
{
Name = barracuda-firewall-network-connection
  Vendor = Barracuda Firewall
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """/box_Firewall_Activity:  """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\/box_Firewall_Activity:\s+[^\s]+\s+({host}[^\s]+)\s+({activity}[^\s:]+):\s+""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}({event_code}[^\|\s]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}[^\|]*\|({protocol}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){2}({src_interface}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){3}(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){4}({src_port}\d+)""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){5}({src_mac}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){6}(?:0.0.0.0|({dest_external_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){7}({dest_port}\d+)""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){8}({app_protocol}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){9}({dest_interface}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){10}({rule}[^\|]+)\|""",
    """\s+(Allow|Remove|LocalRemove|LocalAllow):\s+([^\|]*\|){11}({outcome}[^\|]+)\|""",
    """\s+(Drop|Block|LocalBlock):\s+([^\|]*\|){11}({failure_reason}[^\|]+)\|""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){12}(?:0.0.0.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){13}(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){14}({duration}\d+)""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){16}({bytes_in}\d+)""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){17}({bytes_out}\d+)""",
    """\/box_Firewall_Activity:\s+([^\s]+\s+){3}([^\|]*\|){20}({user}[^\|]+)\|"""
  ]
}
```