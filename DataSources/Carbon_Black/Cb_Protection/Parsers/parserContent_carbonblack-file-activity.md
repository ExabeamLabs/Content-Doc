#### Parser Content
```Java
{
Name = carbonblack-file-activity
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Cb Protection event:""", """subtype="""", """type=""", """policy=""", """file_name=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\sdate="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """({host}[\w.\-]+)\s(\-\s)+Cb Protection event:"""
    """\stext="({additional_info}[^"]+)"""",
    """\stype="({file_type}[^"]+)"""",
    """\ssubtype="({event_code}[^"]+)"""",
    """\shostname="(({domain}[^"\\]+)\\)?({dest_host}[^"\\]+)"""",
    """\susername="(({domain}[^"\\]+)\\)?({user}[^"\\]+)"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]+)""",
    """\spolicy="+({policy}[^"]+)"""",
    """\sfile_path="({file_path}({file_parent}[^"]+?)(\\({file_name}[^"\\]+?))?)"""",
    """\sfile_name="({file_name}[^"]+?(\.({file_ext}[^".]+?))?)"""",
    """\sprocess="({process}(({directory}[^"]+?)\\)?({process_name}[^"\\]+?))""""
    """\sfile_hash="({file_hash}\w+)"""
    
  ]
   DupFields = [ "event_code->accesses","directory->process_directory" ]
}
```