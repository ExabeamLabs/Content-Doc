#### Parser Content
```Java
{
Name = cef-bromium-security-alert-1
  Conditions = [ """|Bromium, Inc.|vSentry|""", """suser=""", """Isolation threat recorded""" ]
}

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
    """\s({host}[\w\-.]+)\sCEF:\d+\|Bromium, Inc.\|""",
    """\|Bromium, Inc.\|([^\|]*\|){3}({alert_name}[^\|]+)""",
    """\|Bromium, Inc.\|([^\|]*\|){4}({alert_severity}\d+)""",
    """(\s|\|)shost=({src_host}[^\s]+)""",
    """(\s|\|)src=({src_ip}[\da-fA-F\.:]+)""",
    """(\s|\|)suser=({user}[^\s@]+)@?.+?\s(\w+=|$)""",
    """(\s|\|)fname=({malware_url}.+?)\s+(\w+=|$)""",
    """(\s|\|)msg=({additional_info}.+?)\s+(\w+=|$)"""
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```