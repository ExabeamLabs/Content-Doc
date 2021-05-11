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
     """\smachine="{1,20}\\*(({src_ip}[A-Fa-f:\d.]+)|({src_host}[^"]+))\s{0,100}"{1,20}\s{0,100}\w+=""",
     """\suser="({user}[^"]+)"""",
     """\sstatus="([^,]+,)*({activity}[^"]+)"""",
     """\sstatus="([^,],)*({activity}[^,]+),error""",
     """\sstatus="({additional_info}[^"]+)"""",
     """({outcome}error)""",
     """\sprinter="({printer_name}[^"]+)"""",
     """\sdocument="{1,20}\s{0,100}({object}.+?)\s{0,100}"{1,20}""",
     """\ssize_bytes=({bytes}\d{1,100})""",
     """\spage_printed=({num_pages}\d{1,100})""",
     """\stotal_pages=({num_pages}\d{1,100})""",
     """[\[\(]+({access}Read-Only)[\]\)]+"""
           ]
}
```