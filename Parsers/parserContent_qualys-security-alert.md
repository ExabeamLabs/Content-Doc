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
    """\sIP="({src_ip}[^"]+)""",
    """\sOS="({os}[^"]+)""",
    """\sNETBIOS="({src_host}[^"]+)""",
    """\sSEVERITY=({alert_severity}\d+)""",
    """\sTAGS="({alert_name}[^",]+)""",
    """\sTAGS="({additional_info}[^"]+)""",
  ]
}

{
  Name = dell-file-operations-1
  Vendor = Dell
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|SMB|""","""|OPEN|""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)\s+({host}[\w\-.]+)\s+([^\[\s]*)?\[[^\]]*\]:?\s+({user_sid}[^\s\|]+)\|({user_uid}[^\|]*)\|({server_name}[^\|]+)\|({zone_id}[^\|]*)\|({src_ip}[A-Fa-f:\d.]+)\|({protocol}[^\|]*)\|({accesses}OPEN)\|({outcome}[^\|\s]*)\|({desire_access}[^\|]*)\|({file_type}[^\|]*)\|({create_result}[^\|]*)\|(|({inode}[^\|]*))\|(|({file_path}({file_parent}[^"\|]*?)[\\\/]*({file_name}[^\\\/"\|]+?(\.({file_ext}[^\\\.\s"\|]+))?)))\s+$""",
  ]
}
```