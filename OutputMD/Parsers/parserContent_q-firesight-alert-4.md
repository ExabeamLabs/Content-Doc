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
    """\WDeviceAddress=({host}[\w\-.]+)""",
    """\WeventId=({alert_id}\d+)""",
    """\WsourceAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """\WdestinationAddress=({dest_ip}[A-Fa-f:\d.]+)""",
    """\WsourcePortOrICMPType=({src_port}\d+)""",
    """\WdestinationPortOrICMPCode=({dest_port}\d+)""",
    """\WuserId=({user}[^\s]+)""",
    """\Wrule.message=({alert_name}.+?)\s+([\w\.]+=|$)""",
    """\WpriorityRef=({alert_severity}.+?)\s+([\w\.]+=|$)""",
    """\WrecordType=({alert_type}.+?)\s+([\w\.]+=|$)""",
  ]
}
```