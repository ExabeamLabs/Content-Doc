#### Parser Content
```Java
{
Name = s-trendmicro-security-alert-2
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/dd/yyyy HH:mm:ss"
  Conditions = [ """TMCM:SLF_INCIDENT_EVT_CCCA""" ]
  Fields = [
    """\sEvent time \(local\)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sTMCM server="({host}[^"]{1,2000})""",
    """\sSecurity agent ip="({src_ip}[^"]{1,2000})""",
    """\sPolicy rule="({alert_name}[^"]{1,2000})""",
    """\sC&C risk level="({alert_severity}[^"]{1,2000})""",
    """\sC&C url="({malware_url}[^"]{1,2000})""",
    """\sC&C ip port="({dest_ip}[^"]{1,2000})""",
    """\sC&C channel="({protocol}[^"]{1,2000})""", 
    """Process="({process}[^"]{1,2000})""",
  ]
}
```