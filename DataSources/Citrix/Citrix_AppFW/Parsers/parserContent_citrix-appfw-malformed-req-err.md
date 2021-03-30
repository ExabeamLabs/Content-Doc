#### Parser Content
```Java
{
Name = citrix-appfw-malformed-req-err
  Product = Citrix AppFW
  Vendor = Citrix
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ APPFW """, """PPE""", """ AF_MALFORMED_REQ_ERR """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\s({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s+(GMT|({host}\S+))\s+({interface_in}\S+)\s+:\s+(\S+\s+){2}({event_name}\S+)\s+({event_code}\S+)\s+\d+\s+:\s+({src_ip}[A-Fa-f:\d.]+)\s+({alert_id}\S+)\s+\S+\s+({result}[^<]+)\s+<({action}[^>]+)>""",
  ]
  DupFields = ["event_name->alert_name"]
}
```