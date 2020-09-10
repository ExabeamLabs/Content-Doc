#### Parser Content
```Java
{
Name = s-microsoft-print-activity
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = ["""driver_name=""", """print_processor=""" , """data_type=""" ]
  Fields = [
     """\ssubmitted_time="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
     """exabeam_host=({host}[\w.\-]+)""",
     """\smachine="+\\*(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^"]+))\s*"+\s*\w+=""",
     """\suser="({user}[^"]+)"""",
     """\sstatus="([^,]+,)*({activity}[^"]+)"""",
     """\sstatus="([^,],)*({activity}[^,]+),error""",
     """\sstatus="({additional_info}[^"]+)"""",
     """({outcome}error)""",
     """\sprinter="({printer_name}[^"]+)"""",
     """\sdocument="+\s*({object}.+?)\s*"+""",
     """\ssize_bytes=({bytes}\d+)""",
     """\spage_printed=({num_pages}\d+)""",
     """\stotal_pages=({num_pages}\d+)""",
     """[\[\(]+({access}Read-Only)[\]\)]+"""
           ]
}
```