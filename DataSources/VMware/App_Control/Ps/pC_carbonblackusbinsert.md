#### Parser Content
```Java
{
Name = carbonblack-usb-insert
  Vendor = VMware
  Product = App Control
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="Device attached""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s(\-\s)+Cb Protection event:"""
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """\stext="({activity_details}[^"]{1,2000})"""",
    """\ssubtype="({event_code}[^"]{1,2000})"""",
    """\shostname="(({domain}[^"\\]{1,2000})\\)?({dest_host}[^"\\]{1,2000})"""",
    """\susername="(({domain}[^"\\]{1,2000})\\)?({user}[^"\\]{1,2000})"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sprocess="({process}(({directory}[^"]{1,2000}?)\\)?({process_name}[^"\\]{1,2000}?))"""",
    """Device '({device_type}[^'(]{1,2000}?)\s{0,100}\(""",
    """\(S\/N:\s{0,100}({device_id}[^)]{1,2000})\)"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```