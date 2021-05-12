#### Parser Content
```Java
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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}(([\+\-]\d{1,100}:\d{1,100})|Z))\s{1,100}({host}[\w\-.]+)\s{1,100}([^\[\s]*)?\[[^\]]*\]:?\s{1,100}({user_sid}[^\s\|]+)\|({user_uid}[^\|]*)\|({server_name}[^\|]+)\|({zone_id}[^\|]*)\|({src_ip}[A-Fa-f:\d.]+)\|({protocol}[^\|]*)\|({accesses}OPEN)\|({outcome}[^\|\s]*)\|({desire_access}[^\|]*)\|({file_type}[^\|]*)\|({create_result}[^\|]*)\|(|({inode}[^\|]*))\|(|({file_path}(|({file_parent}[^"\|]*?))[\\\/]*({file_name}[^\\\/"\|]+?(\.({file_ext}[^\\\.\s"\|\/\d]+))?)))\s{1,100}$""",
  ]
}
```