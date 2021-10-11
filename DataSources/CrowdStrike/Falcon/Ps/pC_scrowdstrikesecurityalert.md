#### Parser Content
```Java
{
Name = s-crowdstrike-security-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"DetectionSummaryEvent"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"DetectName":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"Technique":"({alert_name}[^"]{1,2000})"""",
    """"Severity":\s{0,100}({alert_severity}[^",]{1,2000})""",
    """"DetectId":\s{0,100}"({alert_id}[^"]{1,2000})""",
    """({additional_info_1}"DocumentsAccessed":\s{0,100}[^\]]{1,2000}\]).*?({additional_info_2}"ExecutablesWritten":\s{0,100}[^\]]{1,2000}\])""",
    """"FileName":\s{0,100}"(|({process_name}[^"]{1,2000}))"""",
    """"FilePath":\s{0,100}"(|({file_path}[^"]{1,2000}))"""",
    """"CommandLine"{1,20}:\s{0,100}"{1,20}\\{0,25}"{0,20}({command_line}[^\n]{1,2000}?)\\{0,25}\s{0,100}"{1,20},""",
    """"SensorId":\s{0,100}"({sensor_id}[^"]{1,2000})""",
    """"ComputerName":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"LocalIP":\s{0,100}"({src_ip}[^"]{1,2000})""",
    """"ComputerName":\s{0,100}"({src_host}[^"]{1,2000}).*?"LocalAddress":\s{0,100}"({src_ip}[^"]{1,2000})","LocalPort":\s{0,100}({src_port}\d{1,100}),"RemoteAddress":\s{0,100}"({dest_ip}[^"]{1,2000})","RemotePort":\s{0,100}({dest_port}\d{1,100}),"ConnectionDirection":\s{0,100}0""",
    """"ComputerName":\s{0,100}"({dest_host}[^"]{1,2000}).*?"LocalAddress":\s{0,100}"({dest_ip}[^"]{1,2000})","LocalPort":\s{0,100}({dest_port}\d{1,100}),"RemoteAddress":\s{0,100}"({src_ip}[^"]{1,2000})","RemotePort":\s{0,100}({src_port}\d{1,100}),"ConnectionDirection":\s{0,100}1""",
    """"MD5String":\s{0,100}"(|({md5}[^"]{1,2000}))"""",
    """"UserName":\s{0,100}"(|N/A|({user}[^"]{1,2000}))"""",
    """"FalconHostLink":\s{0,100}"({falcon_host_link}[^"]{1,2000})"""",
    """"DetectDescription":\s{0,100}"({detect_description}[^"]{1,2000})""",
    """"GrandparentImageFileName\\*"{1,20}:\s{0,100}\\*"{1,20}({grandparent_image_filename}[^,]{1,2000}?)\\*"{1,20},""",
    """"GrandparentCommandLine\\*"{1,20}:\s{0,100}\\*"{1,20}({grandparent_command_line}[^},]{1,2000}?)\\*\s{0,100}"{1,20}(,|})""",
    """"ParentImageFileName\\*"{1,20}:\s{0,100}\\*"{1,20}({parent_image_filename}[^,]{1,2000}?)\\*"{1,20},""",
    """"ParentCommandLine\\*"{1,20}:\s{0,100}\\*"{1,20}({parent_command_line}[^,]{1,2000}?)\s{0,100}"{1,20},""",
    """"((?i)SHA256|SHA256String|SHA256HashData)\\*"{1,20}:\s{0,100}\\*"{1,20}({sha256}[^,]{1,2000}?)\\*"{1,20},""",
    """"PatternDispositionDescription\\*"{1,20}:\s{0,100}\\*"{1,20}({pattern_disposition_description}[^"]{1,2000})""",
    """"BootupSafeguardEnabled":\s{0,100}({bootup_safeguard_enabled}true|false)""",
    """"QuarantineFile"{1,20}:\s{0,100}({quarantine_file}true|false)""",
    """"QuarantineMachine"{1,20}:\s{0,100}({quarantine_machine}true|false)""",
    """"Detect"{1,20}:\s{0,100}({detect}true|false)""",
    """"RegistryOperationBlocked"{1,20}:\s{0,100}({registry_operation_blocked}true|false)""",
    """"KillParent"{1,20}:\s{0,100}({kill_parent}true|false)""",
    """"FsOperationBlocked"{1,20}:\s{0,100}({fs_operation_blocked}true|false)""",
    """"OperationBlocked"{1,20}:\s{0,100}({operation_blocked}true|false)""",
    """"KillProcess"{1,20}:\s{0,100}({kill_process}true|false)""",
    """"ProcessBlocked"{1,20}:\s{0,100}({process_blocked}true|false)""",
    """"PolicyDisabled"{1,20}:\s{0,100}({policy_disabled}true|false)""",
    """"SensorOnly"{1,20}:\s{0,100}({sensor_only}true|false)""",
    """"CriticalProcessDisabled"{1,20}:\s{0,100}({critical_process_disabled}true|false)""",
    """"KillSubProcess"{1,20}:\s{0,100}({kill_sub_process}true|false)""",
    """"Rooting"{1,20}:\s{0,100}({rooting}true|false)""",
    """"InddetMask"{1,20}:\s{0,100}({inddet_mask}true|false)""",
    """"Indicator"{1,20}:\s{0,100}({indicator}true|false)"""
  ]
  DupFields = [ "command_line->malware_url", "falcon_host_link->additional_info" ]
  SOAR {		
    IncidentType = "malware"		
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]		
    NameTemplate = """CrowdStrike Alert ${alert_name} found"""		
    ProjectName = "SOC"		
    EntityFields = [		
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]},		
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}		
    ]		
   }
```