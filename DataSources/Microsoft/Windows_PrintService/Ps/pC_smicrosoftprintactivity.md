#### Parser Content
```Java
{
Name = s-microsoft-print-activity
  Vendor = Microsoft
  Product = Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = ["""driver_name=""", """print_processor=""" , """data_type=""" ]
  Fields = [
     """\ssubmitted_time="({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
     """exabeam_host=({host}[\w.\-]{1,2000})""",
     """\smachine="{1,20}\\*(({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[^"]{1,2000}))\s{0,100}"{1,20}\s{0,100}\w+=""",
     """\suser="({user}[^"]{1,2000})"""",
     """\sstatus="([^,]{1,2000},)*({activity}[^"]{1,2000})"""",
     """\sstatus="([^,],)*({activity}[^,]{1,2000}),error""",
     """\sstatus="({additional_info}[^"]{1,2000})"""",
     """({outcome}error)""",
     """\sprinter="({printer_name}[^"]{1,2000})"""",
     """\sdocument="{1,20}\s{0,100}({object}.+?)\s{0,100}"{1,20}""",
     """\ssize_bytes=({bytes}\d{1,100})""",
     """\spage_printed=({num_pages}\d{1,100})""",
     """\stotal_pages=({num_pages}\d{1,100})""",
     """[\[\(]{1,2000}({access}Read-Only)[\]\)]{1,2000}"""
           ]
}
```