#### Parser Content
```Java
{
Name = s-sharepoint-file-download
  Vendor = SharePoint
  Product = SharePoint
  Lms = Splunk
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """<custom_condition_cont-6772>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+({src_ip}[^\s]+)\s+GET\s+(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\.\s"]+))?)))\s+(\S+\s+){2}(-|(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+))\s+\S+\s+({user_agent}.+?)\s+({outcome}\d+)\s+\d+\s+\d+\s+({bytes}\d+)\s+$""",
  ]
}
```