#### Parser Content
```Java
{
Name = leef-carbonblack-file-alert
  Vendor = VMware
  Product = App Control
  Lms = QRadar
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """LEEF:""", """|Carbon_Black|Protection|""", """fileName =""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]{1,2000})\s{1,100}LEEF:""",
    """\WdevTime=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\WreceivedTime=({received_time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\Wcat=(|({alert_type}.+?))\s{1,100}(\w+=|$)""",
    """\Wsev=(|({alert_severity}.+?))\s{1,100}(\w+=|$)""",
    """\WexternalId=(|({alert_id}.+?))\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WsrcHostName =(({domain}[^\\\s]{1,2000})\\+)?({src_host}[\w\-.]{1,2000})""",
    """\WsrcProcess=(|({process}({directory}[^,]{0,2000}?)(\\+({process_name}[^\\,]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """\WusrName =(({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
    """\WfilePath=(|({file_path}(({file_parent}[^=]{1,2000}[^\\])\\+)?({file_name}.+?)))\s{1,100}(\w+=|$)""",
    """\WfileName =(|({file_name}[^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """\WfileHash=(|({old_hash}.+?))\s{1,100}(\w+=|$)""",
    """\WdstHostName =({dest_host}[\w\-.]{1,2000})""",
    """\WruleName =(|({rule}.+?))\s{1,100}(\w+=|$)""",
    """\WinstallerFileName =(|({installer_file_name}.+?))\s{1,100}(\w+=|$)""",
    """\Wpolicy=(|({policy}.+?))\s{1,100}(\w+=|$)""",
    """\|Carbon_Black\|Protection\|([^\|]{0,2000}?\|){1}({alert_name}[^\|]{1,2000})\|""",
    """\|Carbon_Black\|Protection\|([^\|]{0,2000}?\|){1}({accesses}[^\|]{1,2000})\|""",
    """\|Carbon_Black\|Protection\|([^\|]{0,2000}?\|){1}({accesses}[^\|]{1,2000}?)(\s{0,100}\([^|]{1,2000})?\|""",
  ]
  DupFields = [ "old_hash->new_hash" ]


}
```