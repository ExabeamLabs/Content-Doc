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
    """\s({host}[\w\-.]{1,2000})\s{1,100}StealthWatch\[""",
    """\Wstart=({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """\Wsrc=(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdst=(0.0.0.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\Wmsg=({alert_name}[^\|\=]{1,2000}?)\.?\s{0,100}(\||$)""",
    """\Wcat=({alert_type}[^\|\=]{1,2000}?)\.?\s{0,100}(\||$)""",
    """\WalarmID=({alert_id}[^\|\=]{1,2000}?)\s{0,100}(\||$)""",
    """\WalarmSev=({alert_severity}[^\|\=\s]{1,2000}?)\s{0,100}(\||$)""",
    """\Wdomain=({domain}[^\|\=\s]{1,2000}?)\s{0,100}(\||$)""",
    """\Wfullmessage=({additional_info}[^\|]{1,2000}?)\s{0,100}(\||$)"""
  ]


}
```