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
    """exabeam_host=({host}[\w.\-]+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """<Computer>({src_host}.+?)</Computer>""",
    """<EventData><Data>({alert_name}.+?)</Data><Data>({file_path}({file_parent}[^<>]+?)?({file_name}[^<>\\\/]*?(\.({file_ext}\w+))?))(\\\w+)?</Data><Data>.*?</Data><Data>({alert_type}.+?)</Data><Data>.*?</Data><Data>({outcome}.+?)\.?\s*</Data>""",
    """<Computer>({src_host}.+?)</Computer>""",
    """C:\\Users\\({user}[^\\<>]+)""",
    """</Message><Level>({alert_severity}[^\<]+)""",
  ]
}
```