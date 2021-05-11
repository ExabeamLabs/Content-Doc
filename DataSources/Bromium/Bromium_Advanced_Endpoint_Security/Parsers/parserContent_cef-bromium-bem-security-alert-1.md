#### Parser Content
```Java
{
Name = cef-bromium-bem-security-alert-1
  Vendor = Bromium
  Product = Bromium Advanced Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "|Bromium, Inc.|BEM|","|Host threat recorded|" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({host}[\w\-.]+)\sCEF:\d{1,100}\|Bromium, Inc.\|""",
    """\|Bromium, Inc.\|([^\|]*\|){3}({alert_name}[^\|]+)""",
    """\|Bromium, Inc.\|([^\|]*\|){4}({alert_severity}\d{1,100})""",
    """(\s|\|)shost=({src_host}[^\s]+)""",
    """(\s|\|)src=({src_ip}[\da-fA-F\.:]+)""",
    """(\s|\|)suser=({user}[^\s@]+)@?.+?\s(\w+=|$)""",
    """(\s|\|)cs1=({process}({directory}(?:[^\s]+)?[\\\/]+)?({process_name}[^\\\/]+?))\s{1,100}cs1Label=Resources""",
    """(\s|\|)msg=({additional_info}.+?)\s{1,100}(\w+=|$)"""
  ]
  DupFields = [ "alert_name->alert_type","directory->process_directory" ]
}
```