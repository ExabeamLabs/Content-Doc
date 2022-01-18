#### Parser Content
```Java
{
Name = carbonblack-process-created
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="Execution allowed""", """ process=""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s(\-\s)+Cb Protection event:"""
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """\stext="({additional_info}[^"]{1,2000})"""",
    """\ssubtype="({event_code}[^"]{1,2000})"""",
    """\shostname="(({domain}[^"\\]{1,2000})\\)?({dest_host}[^"\\]{1,2000})"""",
    """\susername="(({domain}[^"\\]{1,2000})\\)?({user}[^"\\]{1,2000})"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sprocess="({process}(({directory}[^"]{1,2000}?)\\)?({process_name}[^"\\]{1,2000}?))"""",
    """\sfile_path="({file_path}[^"]{1,2000})"""",
    """\sfile_name="({file_name}[^"]{1,2000})"""",
  ]
  DupFields = [ "directory->process_directory" ]


}
```