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
    """\WDeviceAddress=({host}[\w\-.]{1,2000})""",
    """\WfileEventData.sourceAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WfileEventData.destinationAddress=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WfileEventData.fileName=({file_name}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\WfileEventData.uri=({malware_url}.+?)\s{1,100}fileEventData.signature=""",
    """\WfileEventData.sourcePort=({src_port}\d{1,100})""",
    """\WfileEventData.destinationPort=({dest_port}\d{1,100})""",
    """\WfileEventData.userRef=({user}[^\s]{1,2000})""",
    """\WrecordType=({alert_name}.+?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """\WfileEventData.threatScore=({alert_severity}\d{1,100})""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```