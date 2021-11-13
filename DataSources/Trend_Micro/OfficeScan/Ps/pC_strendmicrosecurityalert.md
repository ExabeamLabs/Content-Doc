#### Parser Content
```Java
{
Name = s-trendmicro-security-alert
  Conditions = [ """TMCM:SLF_INCIDENT_EVT_VIRUS_FOUND_CLEAN_SUCCESS""" ]

s-trendmicro-security-alert = {
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/dd/yyyy HH:mm:ss"
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}TMCM:({alert_type}\w+)""",
    """\sEvent time \(local\)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\s(Virus|Grayware\/Spyware)="({alert_name}[^"]{1,2000})""",
    """\sInfected file="(N\/A|({file_name}[^"]{1,2000}?(\.({file_ext}\w+))?))"""",
    """\sFile path="({file_parent}[^"]{1,2000})""",
    """\sAction taken="({action}[^"]{1,2000})""",
    """\sResult="({outcome}[^"]{1,2000})""",
    """\sInfection source="(N\/A|({src_host}[^"]{1,2000}))""",
    """\sInfection source IP="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sDomain="({domain}[^"]{1,2000})""",
    """\sUser="(({domain}[^"]{1,2000}?)\s{0,100}[\\\/]{1,2000})?({user}[^"\\\/]{1,2000}?)\s{0,100}"""",
    """\sScanMethod="(N\/A|({alert_type}[^"]{1,2000}))""",
    """\sInfection destination="({dest_host}[^"]{1,2000})""",
    """\sInfection destination IP="({dest_ip}[a-fA-F\d.:]{1,2000})""",
  ]
  DupFields = ["file_name->process_name"
}
```