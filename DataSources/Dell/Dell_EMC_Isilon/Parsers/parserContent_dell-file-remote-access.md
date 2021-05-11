#### Parser Content
```Java
{
Name = dell-file-remote-access
  Vendor = Dell
  Product = Dell EMC Isilon
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|SMB|""","""|LOGON|""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]+)\s{1,100}\[[^\]]*\]\s{1,100}({user_sid}[^\s\|]+)\|({dest_host}[^\|]+)\|({zone_id}[^\|]*)\|({src_ip}[A-Fa-f:\d.]+)\|({protocol}[^\|]*)\|({event_name}LOGON)\|({outcome}[^\|]*)\|(({domain}[^\\\s\|]*)\\+)?({src_host}[^\|\s]+)""",
  ]
}
```