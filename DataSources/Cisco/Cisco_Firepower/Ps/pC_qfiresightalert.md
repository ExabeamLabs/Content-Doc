#### Parser Content
```Java
{
Name = q-firesight-alert
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "dd MMMM yyyy HH:mm:ss"
  Conditions = [ """DeviceType=Estreamer""", """recordType=IPS_IMPACT_ALERT""" ]
  Fields = [
      """\stimestamp=({time}\d\d \w{3} \d{4} \d\d:\d\d:\d\d)""",
      """\sDeviceAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\simpactAlertData.sourceAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\simpactAlertData.destinationAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\s\[Priority: ({alert_severity}\d{1,100})\]""",
      """\simpactAlertData.description=\[[^\]]{1,2000}\] "({alert_name}[^"]{1,2000})""",
      """\s\[Classification: ({alert_type}[^\]]{1,2000})\]"""
  ]
}
```