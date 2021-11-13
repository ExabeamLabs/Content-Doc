#### Parser Content
```Java
{
Name = sftp-file-read
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """ sftp-""", """"Opened Directory"""" ]

sftp-events = {
  Vendor = SFTP
  Product = SFTP
  Lms = Direct
  TimeFormat = "EEE ddMMMyy HH:mm:ss"
  Fields = [
    """({host}[\w\-.]{1,2000})\s{1,100}sftp-[^",]{1,2000}"({time}\w+\s{1,100}\d{1,100}\w+\d{1,100}\s{1,100}\d\d:\d\d:\d\d)""",
    """ sftp-.*?("[^"]{0,2000}",){1}"({accesses}[^",]{1,2000})"""",
    """ sftp-.*?("[^"]{0,2000}",){2}"(|({user}[^",\s]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){3}"(|({src_host}[\w\-.]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){4}"(|({src_ip}[A-Fa-f:\d.]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){5}"(|({dest_ip}[A-Fa-f:\d.]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){6}"(|({dest_port}\d{1,100}))"""",
    """ sftp-.*?("[^"]{0,2000}",){8}"(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\.\s"]{1,2000}))?)))"""",
    """ sftp-.*?("[^"]{0,2000}",){9}"(|({bytes}[^"]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){11}"(|({user_agent}[^"]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){12}"(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\.\s"]{1,2000}))?)))"""",
    """ sftp-.*?("[^"]{0,2000}",){13}"(|({src_file_dir}[^"]{1,2000}\\+)?({src_file_name}[^"\\\/]{1,2000}))"""",
    """ sftp-.*?("[^"]{0,2000}",){14}"(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\.\s"]{1,2000}))?)))"""",
  ]
  DupFields = [ "host->dest_host", "accesses->action" 
}
```