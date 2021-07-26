#### Parser Content
```Java
{
Name = trend-micro-alert-8
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[LogNetworkVirus""", """Network Virus Name=""", """Victim IP=""" ]
  Fields = [
    """\d{1,100} ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """Network Virus Name="({alert_name}[^"]{1,2000})"""",
    """Domain="({domain}[^"]{1,2000})""",
    """User="({user}[^"]{1,2000})""",
    """Attacker IP="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """Device name="({src_host}[^"]{1,2000})""",
    """Victim IP="({src_ip}[a-fA-F\d.:]{1,2000})"""
  ]
  DupFields = [ "alert_name->alert_type", "src_host->host" ]
}
```