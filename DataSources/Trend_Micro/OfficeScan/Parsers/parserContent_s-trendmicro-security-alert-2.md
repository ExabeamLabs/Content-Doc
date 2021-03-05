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
    """\sEvent time \(local\)="({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sTMCM server="({host}[^"]+)""",
    """\sSecurity agent ip="({src_ip}[^"]+)""",
    """\sPolicy rule="({alert_name}[^"]+)""",
    """\sC&C risk level="({alert_severity}[^"]+)""",
    """\sC&C url="({malware_url}[^"]+)""",
    """\sC&C ip port="({dest_ip}[^"]+)""",
    """\sC&C channel="({protocol}[^"]+)""", 
    """Process="({process}[^"]+)""",
  ]
}
```