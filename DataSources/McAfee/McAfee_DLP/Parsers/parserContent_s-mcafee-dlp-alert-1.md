#### Parser Content
```Java
{
Name = s-mcafee-dlp-alert-1
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """, classification""", """, dlpAgentVersion=""", """, incidentId=""", """, policyName=""" ]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\Wclassification="({pci_hits}\S+)\s{1,100}\[({phi_hits}.+?)\](\s{1,100}\(({pii_hits}\d{1,100})\))?""",
      """\WincidentId="({alert_id}[^"]{1,2000})""",
      """\WinsertionTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\WruleNames="({alert_name}[^"]{1,2000})""",
      """\Wseverity="({alert_severity}[^"]{1,2000})""",
      """\WtotalContentSize="({bytes}[^"]{1,2000})""",
      """\Wdestination="({additional_info}[^"]{1,2000})""",
      """\WcomputerName="({src_host}[^"]{1,2000})""",
      """\WipAddress="({src_ip}[^"]{1,2000})""",
      """\WuserName="({user}[^"]{1,2000})""",
      """\WpolicyName="({policy}[^"]{1,2000})""",
      """\WfileName="({target}[^"]{1,2000})""",
      """\WeventType="({alert_type}[^"]{1,2000})""",
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_type->dlpActionTaken", "src_host->dlpDeviceName"]
      NameTemplate = """McAfee DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```