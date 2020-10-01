#### Parser Content
```Java
{
Name = q-firesight-alert-3
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """DeviceType=Estreamer""", """recordType=FILE_MALWARE_EVENT""" ]
  Fields = [
    """\Wtimestamp=({time}\d\d \w{3} \d{4} \d\d:\d\d:\d\d)""",
    """\WDeviceAddress=({host}[\w\-.]+)""",
    """\WfileEventData.sourceAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """\WfileEventData.destinationAddress=({dest_ip}[A-Fa-f:\d.]+)""",
    """\WfileEventData.fileName=({file_name}.+?)\s+([\w\.]+=|$)""",
    """\WfileEventData.uri=({malware_url}.+?)\s+fileEventData.signature=""",
    """\WfileEventData.sourcePort=({src_port}\d+)""",
    """\WfileEventData.destinationPort=({dest_port}\d+)""",
    """\WfileEventData.userRef=({user}[^\s]+)""",
    """\WrecordType=({alert_name}.+?)\s+([\w\.]+=|$)""",
    """\WfileEventData.threatScore=({alert_severity}\d+)""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```