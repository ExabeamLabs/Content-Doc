#### Parser Content
```Java
{
Name = cef-bromium-bem-security-alert
  Vendor = Bromium
  Product = Bromium Advanced Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "|Bromium, Inc.|BEM|","|Host threat file hash|" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s({host}[\w\-.]{1,2000})\sCEF:\d{1,100}\|Bromium, Inc.\|""",
    """\|Bromium, Inc.\|([^\|]{0,2000}\|){3}({alert_name}[^\|]{1,2000})""",
    """\|Bromium, Inc.\|([^\|]{0,2000}\|){4}({alert_severity}\d{1,100})""",
    """(\s|\|)shost=({src_host}[^\s]{1,2000})""",
    """(\s|\|)src=({src_ip}[\da-fA-F\.:]{1,2000})""",
    """(\s|\|)suser=({user}[^\s@]{1,2000})@?.+?\s(\w+=|$)""",
    """(\s|\|)fname=({malware_url}.+?)\s{1,100}(\w+=|$)""",
    """(\s|\|)msg=({additional_info}.+?)\s{1,100}(\w+=|$)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```