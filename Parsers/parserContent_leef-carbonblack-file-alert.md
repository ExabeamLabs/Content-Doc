#### Parser Content
```Java
{
Name = leef-carbonblack-file-alert
  Vendor = Carbon Black
  Product = Cb Protection 
  Lms = QRadar
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """LEEF:""", """|Carbon_Black|Protection|""", """fileName=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+LEEF:""",
    """\WdevTime=({time}\w+\s+\d+\s+\d\d\d\d\s+\d\d:\d\d:\d\d\.\d+ \w+)""",
    """\WreceivedTime=({received_time}\w+\s+\d+\s+\d\d\d\d\s+\d\d:\d\d:\d\d\.\d+ \w+)""",
    """\Wcat=(|({alert_type}.+?))\s+(\w+=|$)""",
    """\Wsev=(|({alert_severity}.+?))\s+(\w+=|$)""",
    """\WexternalId=(|({alert_id}.+?))\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\WsrcHostName=(({domain}[^\\\s]+)\\+)?({src_host}[\w\-.]+)""",
    """\WsrcProcess=(|({process}({directory}[^,]*?)(\\+({process_name}[^\\,]+?))?))\s+(\w+=|$)""",
    """\WusrName=(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
    """\WfilePath=(|({file_path}(({file_parent}[^=]+[^\\])\\+)?({file_name}.+?)))\s+(\w+=|$)""",
    """\WfileName=(|({file_name}[^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s+(\w+=|$)""",
    """\WfileHash=(|({old_hash}.+?))\s+(\w+=|$)""",
    """\WdstHostName=({dest_host}[\w\-.]+)""",
    """\WruleName=(|({rule}.+?))\s+(\w+=|$)""",
    """\WinstallerFileName=(|({installer_file_name}.+?))\s+(\w+=|$)""",
    """\Wpolicy=(|({policy}.+?))\s+(\w+=|$)""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({alert_name}[^\|]+)\|""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({accesses}[^\|]+)\|""",
    """\|Carbon_Black\|Protection\|([^\|]*?\|){1}({accesses}[^\|]+?)(\s*\([^|]+)?\|""",
  ]
  DupFields = [ "old_hash->new_hash" ]
}
```