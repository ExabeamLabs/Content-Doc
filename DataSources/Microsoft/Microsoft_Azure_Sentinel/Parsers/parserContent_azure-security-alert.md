#### Parser Content
```Java
{
Name = azure-security-alert
  Vendor = Microsoft
  Product = Microsoft Azure Sentinel
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"ProductName":"Azure Sentinel"""","""CEF""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""", """dproc=Log Analytics OMS Workspace""" ]
  Fields=[
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"{1,20}AlertName"{1,20}:"{1,20}({alert_name}[^"]{1,2000})""",
    """"{1,20}AlertSeverity"{1,20}:"{1,20}({alert_severity}[^"]{1,2000})""",
    """"{1,20}SystemAlertId"{1,20}:"{1,20}({alert_id}[^"]{1,2000})""",
    """"{1,20}Description"{1,20}:"{1,20}({additional_info}.+?)\s{0,100}"""",
    """"{1,20}RemediationSteps"{1,20}:"{1,20}\[({remediation_steps}[^\]]{1,2000})""",
    """"{1,20}AlertType"{1,20}:"{1,20}({alert_type}[^"]{1,2000})""",
    """"{1,20}TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}StartTime"{1,20}:"{1,20}({start_time}[^"]{1,2000})""",
    """"{1,20}EndTime"{1,20}:"{1,20}({end_time}[^"]{1,2000})""",
    """"IsIncident"{1,20}:({is_incident}[^,]{1,2000})""",
    """"ProcessingEndTime"{1,20}:"{1,20}({processing_end_time}[^"]{1,2000})""",
    """"Machine Name\\"{1,20}:\s{0,100}\\"({src_host}[^"]{1,2000})\\""",
    """"Process Name\\*"{1,20}:\s{0,100}\\*"(({process}({directory}[^.]{1,2000})\\({process_name}[^"]{1,2000}))\\)""",
    """"Command Line\\*"{1,20}:\s{0,100}\\*"{1,20}\\*"{1,20}({command_line}.*?)\\+"""",
    """"User SID\\*"{1,20}:\s{0,100}\\*"{1,20}({user_sid}.*?)\\"""",
    """"Account Logon Id\\*"{1,20}:\s{0,100}\\*"{1,20}({logon_id}[^"]{1,2000})\\""",
    """"Account\\":\s{0,100}\\"{1,20}({domain}[^\\]{0,2000}?)\\{1,25}({user}[^"]{0,2000}?)\\",""",
    """"ActionTaken\\":\s{0,100}\\"{1,20}({action}.*?)\\*"""",
    """"DnsDomain\\":\s{0,100}\\"{1,20}(\s{0,100}|({dns_domain}.*?))\\*"""",
    """"NTDomain\\":\s{0,100}\\"{1,20}(\s{0,100}|({nt_domain}.*?))\\*"""",
    """"IsDomainJoined\\"{1,20}:\s{0,100}({domain_join}\w+)""",
    """"AlertLink":"({malware_url}[^"]{1,2000})""",
    """"HostName\\"{1,20}:\s{0,100}\\"({host}.*?)\\*"""",
    ]
   SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost","malware_url->malwareAttackerFile"]
    NameTemplate = """Microsoft azure security Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```