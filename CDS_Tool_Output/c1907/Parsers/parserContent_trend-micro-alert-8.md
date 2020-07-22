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
    """\d+ ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """Network Virus Name="({alert_name}[^"]+)"""",
    """Domain="({domain}[^"]+)""",
    """User="({user}[^"]+)""",
    """Attacker IP="({dest_ip}[a-fA-F\d.:]+)""",
    """Device name="({src_host}[^"]+)""",
    """Victim IP="({src_ip}[a-fA-F\d.:]+)"""
  ]
  DupFields = [ "alert_name->alert_type", "src_host->host" ]
}
```