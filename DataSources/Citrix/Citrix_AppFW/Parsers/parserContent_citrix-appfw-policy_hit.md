#### Parser Content
```Java
{
Name = citrix-appfw-policy_hit
  Product = Citrix AppFW
  Vendor = Citrix
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ APPFW """, """PPE""", """ APPFW_POLICY_HIT """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\s({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s{1,100}(GMT|({host}\S+))\s{1,100}({interface_in}\S+)\s{1,100}:\s{1,100}(\S+\s{1,100}){2}({event_name}\S+)\s{1,100}({event_code}\S+)\s{1,100}\d{1,100}\s{1,100}:\s{1,100}({src_ip}[A-Fa-f:\d.]+)\s{1,100}({alert_id}\S+)\s{1,100}\S+\s{1,100}({rule}\S+)\s{1,100}({full_url}[^\s]+)\s{1,100}({result}.+)""",
  ]
  DupFields = ["event_name->alert_name"]
}
```