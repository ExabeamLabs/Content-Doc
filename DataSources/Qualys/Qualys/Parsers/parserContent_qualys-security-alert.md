#### Parser Content
```Java
{
Name = qualys-security-alert
  Vendor = Qualys
  Product = Qualys
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, TAGS=""", """, SEVERITY=""" , """ IP=""" , """SCAN"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sIP="({src_ip}[^"]{1,2000})""",
    """\sOS="({os}[^"]{1,2000})""",
    """\sNETBIOS="({src_host}[^"]{1,2000})""",
    """\sSEVERITY=({alert_severity}\d{1,100})""",
    """\sTAGS="({alert_name}[^",]{1,2000})""",
    """\sTAGS="({additional_info}[^"]{1,2000})""",
  ]
}
```