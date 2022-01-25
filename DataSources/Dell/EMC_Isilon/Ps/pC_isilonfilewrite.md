#### Parser Content
```Java
{
Name = isilon-file-write
  Conditions = [ """ Isilon""", """|RENAME|SUCCESS|""" ]

isilon-file-activity = {
  Vendor = Dell
  Product = EMC Isilon
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]{1,2000}\d{1,100}:\d{1,100})""",
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]{1,2000}\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """({user_sid}[^\s\|:\]]{1,2000})\|([^\|]{0,2000}\|){3}({src_ip}[A-Fa-f:\d.]{1,2000})\|({protocol}[^\|]{1,2000})\|({accesses}[^\|]{1,2000})\|({outcome}SUCCESS|FAILED)(:({failure_code}[^\|]{0,2000}))?\|([^\|]{0,2000}\|)?({file_type}FILE|DIR)\|"""
    """\|({file_path}({file_parent}[^"\|][^\|,]{0,2000}?[\\\/]{1,2000})?(|({file_name}[^\\\/\|]{0,2000}?(\.({file_ext}\w+))?)))\s{0,100}$"""   
    """\|FAILED:.*?\|(FILE|DIR)\|({failure_reason}[^\|]{1,2000})""",
  
}
```