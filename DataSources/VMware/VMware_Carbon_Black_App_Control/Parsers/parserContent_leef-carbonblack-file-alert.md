#### Parser Content
```Java
{
Name = leef-carbonblack-file-alert
  Vendor = VMware
  Product = VMware Carbon Black App Control
  Lms = QRadar
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """LEEF:""", """|Carbon_Black|Protection|""", """fileName=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]+)\s{1,100}LEEF:""",
    """\WdevTime=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\WreceivedTime=({received_time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\Wcat=(|({alert_type}.+?))\s{1,100}(\w+=|$)""",
    """\Wsev=(|({alert_severity}.+?))\s{1,100}(\w+=|$)""",
    """\WexternalId=(|({alert_id}.+?))\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WsrcHostName=(({domain}[^\\\s]+)\\+)?({src_host}[\w\-.]+)""",
    """\WsrcProcess=(|({process}({directory}[^,]*?)(\\+({process_name}[^\\,]+?))?))\s{1,100}(\w+=|$)""",
    """\WusrName=(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
    """\WfilePath=(|({file_path}(({file_parent}[^=]+[^\\])\\+)?({file_name}.+?)))\s{1,100}(\w+=|$)""",
    """\WfileName=(|({file_name}[^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s{1,100}(\w+=|$)""",
    """\WfileHash=(|({old_hash}.+?))\s{1,100}(\w+=|$)""",
    """\WdstHostName=({dest_host}[\w\-.]+)""",
    """\WruleName=(|({rule}.+?))\s{1,100}(\w+=|$)""",
    """\WinstallerFileName=(|({installer_file_name}.+?))\s{1,100}(\w+=|$)""",
    """\Wpolicy=(|({policy}.+?))\s{1,100}(\w+=|$)""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({alert_name}[^\|]+)\|""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({accesses}[^\|]+)\|""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({accesses}[^\|]+?)(\s{0,100}\([^|]+)?\|""",
  ]
  DupFields = [ "old_hash->new_hash" ]
}
```