#### Parser Content
```Java
{
Name = trapx-alert
  Vendor = TrapX
  Product = TrapX
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = ["""Intelligence Event""", """|TrapX|""", """Network Scan Detected"""]
  Fields = [
     """rt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s""",
     """cat=({alert_name}[^=]{1,2000}?)\s\w+=""",
     """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
     """deviceNtDomain=({domain}[^=]{1,200})\s\w+=""",
     """dst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
     """dpt=({dest_port}\d{1,100})\s""",
     """spt=({src_port}\d{1,100})\s""",
     """proto=({protocol}[^=]{1,2000})\s\w+=""",
     """\sexternalId=({alert_id}\d{1,100})""",
     """exabeam_host=({host}[^\s]{1,2000})""",
     """CEF:([^|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
     """CEF:([^|]{0,2000}\|){5}({alert_type}[^|]{1,2000})""",
  ]


}
```