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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[[^\]]{0,2000}\]\s{1,100}({user_sid}[^\s\|]{1,2000})\|({user_uid}[^\|]{0,2000})\|({server_name}[^\|]{1,2000})\|({zone_id}[^\|]{0,2000})\|({src_ip}[A-Fa-f:\d.]{1,2000})\|({protocol}[^\|]{0,2000})\|({accesses}WRITE)\|({outcome}[^\|\s]{0,2000})\|({file_type}[^\|]{0,2000})\|({inode}[^\|]{0,2000})\|(|({file_path}({file_parent}[^"\|]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"\|]{1,2000}?(\.({file_ext}[^\\\.\s"\|]{1,2000}))?)))\s{1,100}$""",
    """"fileName"{0,20}:"{0,20}({file_path}(({file_parent}[^"]{1,2000})[\\\/]{1,2000})?(({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^\."]{1,2000}))?)))"{0,20

}
```