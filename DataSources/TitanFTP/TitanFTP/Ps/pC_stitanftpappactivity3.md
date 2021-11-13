#### Parser Content
```Java
{
Name = s-titanftp-app-activity-3
  DataType = "app-activity"
  Conditions = [ """ COMMAND: """, """szInPath="""", """SFTP->SSH_FXP_SETSTAT""" ]

s-titanftp-events = {
  Vendor = TitanFTP
  Product = TitanFTP
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({dest_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({dest_port}\d{1,100})\s{1,100}\d{1,100}\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})\s{1,100}({src_port}\d{1,100})\s{1,100}\d{1,100}\s({user}[^\s]{1,2000})\s{1,100}({bytes}\d{1,100})""",
    """COMMAND:\s{0,100}({accesses}.+?)\s{1,100}([\w\-]{1,2000}=|$)""",
    """szInPath="(|({file_path}({file_parent}[^"]{1,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\.\s"]{1,2000}))?)?))"""",
  ]
  DupFields = [ "dest_ip->host" 
}
```