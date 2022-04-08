#### Parser Content
```Java
{
Name = leef-carbonblack-file-alert-1
  Vendor = VMware
  Product = Carbon Black App Control
  Lms = QRadar
  DataType = "file-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """LEEF:""", """|VMware_Carbon_Black|App_Control|""", """srcHostName =""", """policy=""", """dstHostName =""", """fileThreat=""", """fileTrust=""", """fileId=""" ]
  Fields = [
    """devTime=({time}\w{1,3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d{1,3}\s\w{1,3})""",
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\sLEEF""",
    """\|App_Control\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})""",
    """\Wcat=({alert_type}[^=]{1,2000}?)\s{1,100}\w+=""",
    """sev=({alert_severity}\d{1,100})""",
    """externalId=({alert_id}[^=]{1,2000}?)\s{1,100}\w+=""",
    """src=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """srcHostName =(({domain}[^\\\s]{1,2000})\\{1,20})?({src_host}[^\s]{1,2000})""",
    """srcProcess=({process}({directory}[^=]{0,2000}?[\\\/]{1,2000})?({process_name}[^\\\/=]{1,2000}?))\s{1,100}\w+=""",
    """usrName =(({domain}[^\\\s]{1,2000})\\{1,20})?({user}[^\s]{1,2000})""",
    """fileName =({file_name}[^=]{1,2000}?(\.({file_ext}[^=.]{1,2000}?)?))\s{1,100}\w+=""",
    """filePath=({file_path}({file_parent}[^=]{1,2000}?)[^=\\]{1,2000}?)\s{1,100}\w+=""",
    """dstHostName =({dest_host}[^\s]{1,2000})"""
  ]


}
```