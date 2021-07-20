#### Parser Content
```Java
{
Name = q-firesight-alert-2
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "dd MMMM yyyy HH:mm:ss"
  Conditions = [ """DeviceType=Estreamer""", """recordType=INTRUSION_EVENT_RECORD3""" ]
  Fields = [
      """\stimestamp=({time}\d\d \w{3} \d{4} \d\d:\d\d:\d\d)""",
      """\sDeviceAddress=({host}[^\s]{1,2000})""",
      """\seventId=({alert_id}\d{1,100})""",
      """\ssourceAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdestinationAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\spriority.name=({alert_severity}[^\s]{1,2000})""",
      """\sclassification.description=({alert_name}.+?)\sclassification""",
      """\sclassification.name=({alert_type}.+?)\sclassification"""
  ]
}
```