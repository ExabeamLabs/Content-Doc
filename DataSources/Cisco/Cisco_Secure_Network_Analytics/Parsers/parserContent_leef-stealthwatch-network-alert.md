#### Parser Content
```Java
{
Name = leef-stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = QRadar
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """LEEF""", """StealthWatch[""", """|Lancope|Stealthwatch|""", """alarmID=""", """alarmSev=""" ]
  Fields = [
    """\s({host}[\w\-.]+)\s{1,100}StealthWatch\[""",
    """\Wstart=({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\Wmsg=({alert_name}[^\|\=]+?)\.?\s{0,100}(\||$)""",
    """\Wcat=({alert_type}[^\|\=]+?)\.?\s{0,100}(\||$)""",
    """\WalarmID=({alert_id}[^\|\=]+?)\s{0,100}(\||$)""",
    """\WalarmSev=({alert_severity}[^\|\=\s]+?)\s{0,100}(\||$)""",
    """\Wdomain=({domain}[^\|\=\s]+?)\s{0,100}(\||$)""",
    """\Wfullmessage=({additional_info}[^\|]+?)\s{0,100}(\||$)"""
  ]
}
```