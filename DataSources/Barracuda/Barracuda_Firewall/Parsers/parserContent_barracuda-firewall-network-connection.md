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
    """\/box_Firewall_Activity:\s{1,100}[^\s]{1,2000}\s{1,100}({host}[^\s]{1,2000})\s{1,100}({activity}[^\s:]{1,2000}):\s{1,100}""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}({event_code}[^\|\s]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}[^\|]{0,2000}\|({protocol}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){2}({src_interface}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){3}(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){4}({src_port}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){5}({src_mac}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){6}(?:0.0.0.0|({dest_external_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){7}({dest_port}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){8}({app_protocol}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){9}({dest_interface}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){10}({rule}[^\|]{1,2000})\|""",
    """\s{1,100}(Allow|Remove|LocalRemove|LocalAllow):\s{1,100}([^\|]{0,2000}\|){11}({outcome}[^\|]{1,2000})\|""",
    """\s{1,100}(Drop|Block|LocalBlock):\s{1,100}([^\|]{0,2000}\|){11}({failure_reason}[^\|]{1,2000})\|""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){12}(?:0.0.0.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){13}(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){14}({duration}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){16}({bytes_in}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){17}({bytes_out}\d{1,100})""",
    """\/box_Firewall_Activity:\s{1,100}([^\s]{1,2000}\s{1,100}){3}([^\|]{0,2000}\|){20}({user}[^\|]{1,2000})\|"""
  ]
}
```