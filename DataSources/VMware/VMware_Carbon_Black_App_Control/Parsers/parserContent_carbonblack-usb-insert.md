#### Parser Content
```Java
{
Name = carbonblack-usb-insert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="Device attached""" ]
  Fields = [
    """({host}[\w.\-]+)\s(\-\s)+Cb Protection event:"""
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """\stext="({activity_details}[^"]+)"""",
    """\ssubtype="({event_code}[^"]+)"""",
    """\shostname="(({domain}[^"\\]+)\\)?({dest_host}[^"\\]+)"""",
    """\susername="(({domain}[^"\\]+)\\)?({user}[^"\\]+)"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]+)""",
    """\sprocess="({process}(({directory}[^"]+?)\\)?({process_name}[^"\\]+?))"""",
    """Device '({device_type}[^'(]+?)\s{0,100}\(""",
    """\(S\/N:\s{0,100}({device_id}[^)]+)\)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```