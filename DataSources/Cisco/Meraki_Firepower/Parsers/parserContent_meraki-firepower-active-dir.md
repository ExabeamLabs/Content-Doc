#### Parser Content
```Java
{
Name = meraki-firepower-active-dir
  Vendor = Cisco
  Product = Meraki Firepower
  Lms = Syslog
  DataType = "authentication-successful"
  TimeFormat = "epoch_sec"
  Conditions = [ """Original Address=""", """Active Directory""", """connected to server""" ]
  Fields = [
    """\s({time}\d+).\d+\s""",
    """Original Address=({host}[^\s]+)\s""",
    """events\s*({event_name}.*?)\s*$""",
    """connected to server ({dest_host}[^\s]+) \(({dest_ip}.*?)\)\sas ({domain}[^\/]+)\/({user}[^\s]+)""",
  ]
}
```