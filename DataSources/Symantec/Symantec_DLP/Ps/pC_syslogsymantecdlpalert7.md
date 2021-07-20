#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-7
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Syslog
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Conditions = [ """Incident_Snapshot: """, """Endpoint_Machine: """, """Incident_ID: """, """Policy: """ ]
  Fields = [
    """({host}[^\s]{1,2000})\s{0,100}Incident_Snapshot:""",
    """Occurred:\s{0,100}({time}\w+ \d{1,100}
```