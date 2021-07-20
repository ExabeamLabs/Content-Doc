#### Parser Content
```Java
{
Name = citrix-appfw-fieldconsistency
  Product = Citrix AppFW
  Vendor = Citrix
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ APPFW """, """PPE""", """ APPFW_FIELDCONSISTENCY """ ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\s({time}\d\d\/\d\d\/\d\d\d\d:\d\d:\d\d:\d\d)\s{1,100}(GMT|({host}\S+))\s{1,100}({interface_in}\S+)\s{1,100}:\s{1,100}(\S+\s{1,100}){2}({event_name}\S+)\s{1,100}({event_code}\S+)\s{1,100}\d{1,100}\s{1,100}:\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({alert_id}\S+)\s{1,100}\S+\s{1,100}({rule}\S+)\s{1,100}({full_url}[^\s]{1,2000})\s{1,100}({result}[^<]{1,2000}?)\s{0,100}<({action}[^>]{1,2000})>""",
  ]
  DupFields = ["event_name->alert_name"]
}
```