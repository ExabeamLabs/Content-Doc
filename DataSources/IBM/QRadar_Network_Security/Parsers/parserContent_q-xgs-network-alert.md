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
    """(\||\W)SensorName=(.+?@\s{0,100})?({host}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\W({host}[\w\-\.]{1,2000})\s{0,100}LEEF:""",
    """(\||\W)devTime=({time}\w{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """(\||\W)src=({src_ip}[\da-fA-F\.:]{1,2000})\s{1,100}""",
    """(\||\W)dst=({dest_ip}[\da-fA-F\.:]{1,2000})\s{1,100}""",
    """(\||\W)srcPort=({src_port}\d{1,100})\s{1,100}""",
    """(\||\W)dstPort=({dest_port}\d{1,100})\s{1,100}""",
    """(\||\W)proto=({protocol}.+?)\s{0,100}(\w+=|$)""",
    """(.*?\|){4}({alert_name}[^\|]{1,2000}?)\|""",
    """(\||\W)event-type=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """(\||\W)sev=({alert_severity}.*?)\s{0,100}(\w+=|$)""",
    """(\||\W)nvpdata=({additional_info}.+?)\s(\w+=|$)"""
  ]
}
```