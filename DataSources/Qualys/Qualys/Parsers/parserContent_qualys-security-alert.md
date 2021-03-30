#### Parser Content
```Java
{
Name = qualys-security-alert
  Vendor = Qualys
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, TAGS=""", """, SEVERITY=""" , """ IP=""" , """SCAN"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sIP="({src_ip}[^"]+)""",
    """\sOS="({os}[^"]+)""",
    """\sNETBIOS="({src_host}[^"]+)""",
    """\sSEVERITY=({alert_severity}\d+)""",
    """\sTAGS="({alert_name}[^",]+)""",
    """\sTAGS="({additional_info}[^"]+)""",
  ]
}
```