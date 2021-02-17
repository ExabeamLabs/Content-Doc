#### Parser Content
```Java
{
Name = trapx-alert
  Vendor = TrapX
  Product = TrapX
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "MMM dd yyy HH:mm:ss"
  Conditions = ["""Intelligence Event""", """|TrapX|""", """Network Scan Detected"""]
  Fields = [
     """rt=({time}.+)\ssrc""",
     """cat=({alert_name}.+)\sdevicePayloadId""",
     """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
     """deviceNtDomain=({domain}.+)\sdpt""",
     """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
     """dpt=({dest_port}\d+)\s""",
     """spt=({src_port}\d+)\s""",
     """proto=({protocol}\w+)\s""",
     """\sexternalId=({alert_id}\d+)""",
     """exabeam_host=({host}[^\s]+)""",
  ]
}
```