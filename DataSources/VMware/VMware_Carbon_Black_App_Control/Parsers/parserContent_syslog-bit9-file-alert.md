#### Parser Content
```Java
{
Name = syslog-bit9-file-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "M/dd/yyyy H:mm:ss a"
  Conditions = [ """Bit9 event:""", """ file_name="""", """ subtype="""" ]
  Fields = [
    """\sdate="({time}\d{1,2}\/\d{1,2}\/\d\d\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))"""",
    """\sip_address="({dest_ip}[^"\s]{1,2000}?)"""",
    """\sip_address="({host}[^"\s]{1,2000}?)"""",
    """\shostname="([^"]{1,2000}[\\\/]{1,2000})?({dest_host}[^"\s]{1,2000}?)"""",
    """\shostname="([^"]{1,2000}[\\\/]{1,2000})?({host}[^"\s]{1,2000}?)"""",
    """\ssubtype="({alert_name}[^"]{1,2000}?)"""",
    """\ssubtype="({accesses}[^"]{1,2000}?)(\s{0,100}\([^"]{1,2000})?"""",
    """\stype="({alert_type}[^"]{1,2000}?)"""",
    """\susername="(({domain}[^"\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
    """\sfile_path="({file_path}(({file_parent}[^"]{1,2000})\\+)?({file_name}[^"\\]{1,2000}))"""",
    """\sfile_name="({file_name}[^"]{1,2000})"""",
    """\sfile_hash="({new_hash}[^"]{1,2000})"""",
    """\sprocess="({process}[^"]{1,2000})"""",
  ]
}
```