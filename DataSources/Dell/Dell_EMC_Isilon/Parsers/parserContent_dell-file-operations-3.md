#### Parser Content
```Java
{
Name = dell-file-operations-3
  Vendor = Dell
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|SMB|""","""|WRITE|""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]+)\s{1,100}\[[^\]]*\]\s{1,100}({user_sid}[^\s\|]+)\|({user_uid}[^\|]*)\|({server_name}[^\|]+)\|({zone_id}[^\|]*)\|({src_ip}[A-Fa-f:\d.]+)\|({protocol}[^\|]*)\|({accesses}WRITE)\|({outcome}[^\|\s]*)\|({file_type}[^\|]*)\|({inode}[^\|]*)\|(|({file_path}({file_parent}[^"\|]*?)[\\\/]*({file_name}[^\\\/"\|]+?(\.({file_ext}[^\\\.\s"\|]+))?)))\s{1,100}$""",
    """"fileName"{0,20}:"{0,20}({file_path}(({file_parent}[^"]+)[\\\/]+)?(({file_name}[^"\\\/]+?(\.({file_ext}[^\."]+))?)))"{0,20}
```