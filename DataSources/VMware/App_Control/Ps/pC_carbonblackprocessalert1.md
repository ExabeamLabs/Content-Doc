#### Parser Content
```Java
{
Name = carbonblack-process-alert-1
  Vendor = VMware
  Product = App Control
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Carbon Black App Control event:""", """subtype="Execution block""", """ ip_address=""" ]
  Fields = [
    """\sdate="({time}\d{1,2}\/\d{1,2}\/\d{1,4}\s\d{1,2}:\d{1,2}:\d{1,2}\s(am|AM|PM|pm))"""",
    """\shostname="(({domain}[^\\]{1,2000})\\({host}[^"]{1,2000}))""",
    """\susername="(({domain}[^\\]{1,2000})\\({user}[^"]{1,2000}))"""",
    """\ssubtype="({alert_type}[^"]{1,2000})"""",
    """\sprocess="{1,10}({process}(({directory}[^"]{1,2000})\\({process_name}[^"]{1,2000})))""",
    """\stext="({additional_info}[^"]{1,2000}?)\s{0,10}"""",
    """\sip_address="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\srule_name="({alert_name}[^"]{1,2000})"""",
    """\sprocess_threat="({alert_severity}[^"]{1,2000})"""",
    """\sfile_path="({file_path}[^"]{1,2000})"""",
    """file_name="({file_name}[^"]{1,2000}\.({file_ext}[^"]{1,2000}))""",
    """\spolicy="({policy}[^"]{1,2000})"""",
    ]
    DupFields = [ "alert_type->accesses","directory->process_directory" ]


}
```