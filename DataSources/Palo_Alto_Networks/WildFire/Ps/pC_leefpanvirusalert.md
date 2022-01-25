#### Parser Content
```Java
{
Name = leef-pan-virus-alert
  Conditions = [ """|Palo Alto Networks|PAN-OS""", """|Subtype=virus|""" ]

leef-pan-alert = {
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\.-]{1,2000})(\s{1,100}|,"{1,100})LEEF:""",
    """\|DeviceName =({host}[^\|"]{1,2000}?)\s{0,100}(\||"*$)""",
    """\|Subtype=({alert_type}[^\|]{1,2000})""",
    """\|src=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\|dst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\|Application=({process_name}[^\|]{1,2000})""",
    """\|srcPort=({src_port}\d{1,100})""",
    """\|dstPort=({dest_port}\d{1,100})""",
    """\|proto=({protocol}[^\|]{1,2000})""",
    """\|action=({outcome}[^\|]{1,2000})""",
    """\|Miscellaneous="({additional_info}[^"\|]{1,2000})"""",
    """\|ThreatID=({alert_name}[^\|]{1,2000})""",
    """\|URLCategory=({category}[^\|]{1,2000})""",
    """\|Severity=({alert_severity}[^\|]{1,2000})""",
    """\|ThreatCategory=(?:unknown|({threat_category}[^\|]{1,2000}))""",
    """usrName =({domain}[^\\\|]{1,2000})\\({user}[^\s\|]{1,2000})""",
    """\|SourceZone=({src_network_zone}[^\|]{1,2000}?)\|""",
    """\|DestinationZone=({dest_network_zone}[^\|]{1,2000}?)\|""",
    
}
```