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
      """exabeam_host=({host}[^\s]+)""",
      """\Wclassification="({pci_hits}\S+)\s{1,100}\[({phi_hits}.+?)\](\s{1,100}\(({pii_hits}\d{1,100})\))?""",
      """\WincidentId="({alert_id}[^"]+)""",
      """\WinsertionTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\WruleNames="({alert_name}[^"]+)""",
      """\Wseverity="({alert_severity}[^"]+)""",
      """\WtotalContentSize="({bytes}[^"]+)""",
      """\Wdestination="({additional_info}[^"]+)""",
      """\WcomputerName="({src_host}[^"]+)""",
      """\WipAddress="({src_ip}[^"]+)""",
      """\WuserName="({user}[^"]+)""",
      """\WpolicyName="({policy}[^"]+)""",
      """\WfileName="({target}[^"]+)""",
      """\WeventType="({alert_type}[^"]+)""",
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_type->dlpActionTaken", "src_host->dlpDeviceName"]
      NameTemplate = """McAfee DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```