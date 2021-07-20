#### Parser Content
```Java
{
Name = xml-sophos-security-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<Provider Name='Sophos Anti-Virus'/>""", """<EventData><Data>""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """<Computer>({src_host}.+?)</Computer>""",
    """<EventData><Data>({alert_name}.+?)</Data><Data>({file_path}({file_parent}[^<>]{1,2000}?)?({file_name}[^<>\\\/]{0,2000}?(\.({file_ext}\w+))?))(\\\w+)?</Data><Data>.*?</Data><Data>({alert_type}.+?)</Data><Data>.*?</Data><Data>({outcome}.+?)\.?\s{0,100}</Data>""",
    """<Computer>({src_host}.+?)</Computer>""",
    """C:\\Users\\({user}[^\\<>]{1,2000})""",
    """</Message><Level>({alert_severity}[^\<]{1,2000})""",
  ]
}
```