#### Parser Content
```Java
{
Name = syslog-bit9-file-alert
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "M/dd/yyyy H:mm:ss a"
  Conditions = [ """Bit9 event:""", """ file_name="""", """ subtype="""" ]
  Fields = [
    """\sdate="({time}\d{1,2}\/\d{1,2}\/\d\d\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))"""",
    """\sip_address="({dest_ip}[^"\s]+?)"""",
    """\sip_address="({host}[^"\s]+?)"""",
    """\shostname="([^"]+[\\\/]+)?({dest_host}[^"\s]+?)"""",
    """\shostname="([^"]+[\\\/]+)?({host}[^"\s]+?)"""",
    """\ssubtype="({alert_name}[^"]+?)"""",
    """\ssubtype="({accesses}[^"]+?)(\s*\([^"]+)?"""",
    """\stype="({alert_type}[^"]+?)"""",
    """\susername="(({domain}[^"\\]+)\\+)?({user}[^"]+)"""",
    """\sfile_path="({file_path}(({file_parent}[^"]+)\\+)?({file_name}[^"\\]+))"""",
    """\sfile_name="({file_name}[^"]+)"""",
    """\sfile_hash="({new_hash}[^"]+)"""",
    """\sprocess="({process}[^"]+)"""",
  ]
}
```