#### Parser Content
```Java
{
Name = q-firesight-alert-4
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """DeviceType=Estreamer""", """recordType=INTRUSION_EVENT_RECORD_IPV4""" ]
  Fields = [
    """\Wtimestamp=({time}\d\d \w{3} \d{4} \d\d:\d\d:\d\d)""",
    """\WDeviceAddress=({host}[\w\-.]{1,2000})""",
    """\WeventId=({alert_id}\d{1,100})""",
    """\WsourceAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WdestinationAddress=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WsourcePortOrICMPType=({src_port}\d{1,100})""",
    """\WdestinationPortOrICMPCode=({dest_port}\d{1,100})""",
    """\WuserId=({user}[^\s]{1,2000})""",
    """\Wrule.message=({alert_name}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\WpriorityRef=({alert_severity}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\WrecordType=({alert_type}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
  ]


}
```