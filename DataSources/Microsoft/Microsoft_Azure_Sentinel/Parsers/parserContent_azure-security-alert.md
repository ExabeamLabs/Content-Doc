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
    """exabeam_host=({host}[\w.\-]+)""",
    """"+AlertName"+:"+({alert_name}[^"]+)""",
    """"+AlertSeverity"+:"+({alert_severity}[^"]+)""",
    """"+SystemAlertId"+:"+({alert_id}[^"]+)""",
    """"+Description"+:"+({additional_info}.+?)\s*"""",
    """"+RemediationSteps"+:"+\[({remediation_steps}[^\]]+)""",
    """"+AlertType"+:"+({alert_type}[^"]+)""",
    """"+TimeGenerated"+:"+({time}[^"]+)""",
    """"+StartTime"+:"+({start_time}[^"]+)""",
    """"+EndTime"+:"+({end_time}[^"]+)""",
    """"IsIncident"+:({is_incident}[^,]+)""",
    """"ProcessingEndTime"+:"+({processing_end_time}[^"]+)""",
    """"Machine Name\\"+:\s*\\"({src_host}[^"]+)\\""",
    """"Process Name\\*"+:\s*\\*"(({process}({directory}[^.]+)\\({process_name}[^"]+))\\)""",
    """"Command Line\\*"+:\s*\\*"+\\*"+({command_line}.*?)\\+"""",
    """"User SID\\*"+:\s*\\*"+({user_sid}.*?)\\"""",
    """"Account Logon Id\\*"+:\s*\\*"+({logon_id}[^"]+)\\""",
    """"Account\\":\s*\\"+({domain}.*?)\\+({user}.*?)\\",""",
    """"ActionTaken\\":\s*\\"+({action}.*?)\\*"""",
    """"DnsDomain\\":\s*\\"+(\s*|({dns_domain}.*?))\\*"""",
    """"NTDomain\\":\s*\\"+(\s*|({nt_domain}.*?))\\*"""",
    """"IsDomainJoined\\"+:\s*({domain_join}\w+)""",
    """"AlertLink":"({malware_url}[^"]+)""",
    """"HostName\\"+:\s*\\"({host}.*?)\\*"""",
    ]
   SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost","malware_url->malwareAttackerFile"]
    NameTemplate = """Microsoft azure security Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```