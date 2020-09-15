#### Parser Content
```Java
{
Name = q-xgs-network-alert
  Vendor = IBM
  Product = QRadar Network Security
  Lms = QRadar
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|IBM|ISNP|""", """|cat=""" ]
  Fields = [
    """(\||\W)SensorName=(.+?@\s*)?({host}[^\s]+)\s*(\w+=|$)""",
    """\W({host}[\w\-\.]+)\s*LEEF:""",
    """(\||\W)devTime=({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\||\W)src=({src_ip}[\da-fA-F\.:]+)\s+""",
    """(\||\W)dst=({dest_ip}[\da-fA-F\.:]+)\s+""",
    """(\||\W)srcPort=({src_port}\d+)\s+""",
    """(\||\W)dstPort=({dest_port}\d+)\s+""",
    """(\||\W)proto=({protocol}.+?)\s*(\w+=|$)""",
    """(.*?\|){4}({alert_name}[^\|]+?)\|""",
    """(\||\W)event-type=({alert_type}.+?)\s*(\w+=|$)""",
    """(\||\W)sev=({alert_severity}.*?)\s*(\w+=|$)""",
    """(\||\W)nvpdata=({additional_info}.+?)\s(\w+=|$)"""
  ]
}
```