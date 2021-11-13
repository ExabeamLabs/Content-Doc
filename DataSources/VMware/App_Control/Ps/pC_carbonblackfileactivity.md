#### Parser Content
```Java
{
Name = carbonblack-file-activity
  Vendor = VMware
  Product = App Control
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="""", """type=""", """policy=""", """file_name=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """({host}[\w.\-]{1,2000})\s(\-\s)+Cb Protection event:"""
    """\stext="({additional_info}[^"]{1,2000})"""",
    """\stype="({file_type}[^"]{1,2000})"""",
    """\ssubtype="({event_code}[^"]{1,2000})"""",
    """\shostname="(({domain}[^"\\]{1,2000})\\)?({dest_host}[^"\\]{1,2000})"""",
    """\susername="(({domain}[^"\\]{1,2000})\\)?({user}[^"\\]{1,2000})"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\spolicy="{1,20}({policy}[^"]{1,2000})"""",
    """\sfile_path="({file_path}({file_parent}[^"]{1,2000}?)(\\({file_name}[^"\\]{1,2000}?))?)"""",
    """\sfile_name="({file_name}[^"]{1,2000}?(\.({file_ext}[^".]{1,2000}?))?)"""",
    """\sprocess="({process}(({directory}[^"]{1,2000}?)\\)?({process_name}[^"\\]{1,2000}?))""""
    """\sfile_hash="({file_hash}\w+)"""
    
  ]
   DupFields = [ "event_code->accesses","directory->process_directory" ]


}
```