#### Parser Content
```Java
{
Name = meraki-firepower-active-dir
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Syslog
  DataType = "authentication-successful"
  TimeFormat = "epoch_sec"
  Conditions = [ """Original Address=""", """Active Directory""", """connected to server""" ]
  Fields = [
    """\s({time}\d{1,100}).\d{1,100}\s""",
    """Original Address=({host}[^\s]{1,2000})\s""",
    """events\s{0,100}({event_name}.*?)\s{0,100}$""",
    """connected to server ({dest_host}[^\s]{1,2000}) \(({dest_ip}.*?)\)\sas ({domain}[^\/]{1,2000})\/({user}[^\s]{1,2000})""",
  ]


}
```