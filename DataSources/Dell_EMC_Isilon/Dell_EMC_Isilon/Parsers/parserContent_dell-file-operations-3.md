#### Parser Content
```Java
{
Name = dell-file-operations-3
  Vendor = Dell EMC Isilon
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|SMB|""","""|WRITE|""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+[\+\-]\d+:\d+)\s+({host}[\w\-.]+)\s+\[[^\]]*\]\s+({user_sid}[^\s\|]+)\|({user_uid}[^\|]*)\|({server_name}[^\|]+)\|({zone_id}[^\|]*)\|({src_ip}[A-Fa-f:\d.]+)\|({protocol}[^\|]*)\|({accesses}WRITE)\|({outcome}[^\|\s]*)\|({file_type}[^\|]*)\|({inode}[^\|]*)\|(|({file_path}({file_parent}[^"\|]*?)[\\\/]*({file_name}[^\\\/"\|]+?(\.({file_ext}[^\\\.\s"\|]+))?)))\s+$""",
    """"fileName"*:"*({file_path}(({file_parent}[^"]+)[\\\/]+)?(({file_name}[^"\\\/]+?(\.({file_ext}[^\."]+))?)))"*,"""
 ]
}
```