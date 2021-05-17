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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[[^\]]{0,2000}\]\s{1,100}({user_sid}[^\s\|]{1,2000})\|({dest_host}[^\|]{1,2000})\|({zone_id}[^\|]{0,2000})\|({src_ip}[A-Fa-f:\d.]{1,2000})\|({protocol}[^\|]{0,2000})\|({event_name}LOGON)\|({outcome}[^\|]{0,2000})\|(({domain}[^\\\s\|]{0,2000})\\+)?({src_host}[^\|\s]{1,2000})""",
  ]
}
```