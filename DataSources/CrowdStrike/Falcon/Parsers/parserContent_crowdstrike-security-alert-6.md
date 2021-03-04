#### Parser Content
```Java
{
Name = crowdstrike-security-alert-6
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """"ExternalApiType": "Event_DetectionSummaryEvent"""",  """"Severity"""", """"FalconHostLink""""  ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"ProcessStartTime":\s*({time}\d+)""",
      """"UserName":\s*"({user}[^"@]+)(@({src_host}[^"]+))?"""",
      """"ComputerName":\s*"({src_host}[^"]+)"""",
      """"DetectName":\s*"({alert_name}[^"]+)"""",
      """"ExternalApiType":\s*"({alert_type}[^"]+)"""",
      """"DetectDescription":\s*"({additional_info}[^"]+)"""",
      """"Severity":\s*({alert_severity}\d+)""",
      """"SeverityName":\s*"({alert_severity}[^"]+?)"""",
      """"FileName":\s*"({file_name}[^"]+?)"""",
      """"FilePath":\s*"({file_path}[^"]+?)\\?"""",
      """"CommandLine"+:\s*"+\\*"*({command_line}.+?)\\*\s*"+,""",
      """"CommandLine":\s*"\\"({process}({directory}[^",]+\\\\)?({process_name}[^"\\,]+))\\"""",
      """"LocalIP":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"RemoteAddress":\s*"({dest_ip}[a-fA-F\d.:]+)""",
      """\\*"DetectDescription\\*":\s*\\*"({alert_name}[^"]+)""",
      """"DetectName":\s*"({alert_name}[^"]+)""",
      """"Technique":\s*"({alert_type}[^"]+)""",
      """"LocalAddress":\s*"({src_ip}[^"]+)""",
      """"DetectId"+:\s*"+({alert_id}[^"]+)"""",
      """"MD5String"+:\s*"+({md5}[^"]+)"""",
      """"SHA256String":\s*"({sha256}[^"]+)""",
      """"GrandparentImageFileName\\*"+:\s*\\*"+({grandparent_image_filename}[^,]+?)\\*"+,""",
      """"GrandparentCommandLine\\*"+:\s*\\*"+({grandparent_command_line}[^,]+?)\\*"+,""",
      """"ParentImageFileName\\*"+:\s*\\*"+({parent_image_filename}[^,]+?)\\*"+,""",
      """"ParentCommandLine\\*"+:\s*\\*"+({parent_command_line}[^,]+?)"+,""",
      """"PatternDispositionDescription\\*"+:\s*\\*"+({pattern_disposition_description}[^"]+)""",
      """"FalconHostLink\\*"+:\s*\\*"+({falcon_host_link}[^"]+)""",
      """"BootupSafeguardEnabled":\s*({bootup_safeguard_enabled}true|false)""",
      """"QuarantineFile"+:\s*({quarantine_file}true|false)""",
      """"QuarantineMachine"+:\s*({quarantine_machine}true|false)""",
      """"Detect"+:\s*({detect}true|false)""",
      """"RegistryOperationBlocked"+:\s*({registry_operation_blocked}true|false)""",
      """"KillParent"+:\s*({kill_parent}true|false)""",
      """"FsOperationBlocked"+:\s*({fs_operation_blocked}true|false)""",
      """"OperationBlocked"+:\s*({operation_blocked}true|false)""",
      """"KillProcess"+:\s*({kill_process}true|false)""",
      """"ProcessBlocked"+:\s*({process_blocked}true|false)""",
      """"PolicyDisabled"+:\s*({policy_disabled}true|false)""",
      """"SensorOnly"+:\s*({sensor_only}true|false)""",
      """"CriticalProcessDisabled"+:\s*({critical_process_disabled}true|false)""",
      """"KillSubProcess"+:\s*({kill_sub_process}true|false)""",
      """"Rooting"+:\s*({rooting}true|false)""",
      """"InddetMask"+:\s*({inddet_mask}true|false)""",
      """"Indicator"+:\s*({indicator}true|false)"""
    ]
    DupFields = [ "directory->process_directory", "falcon_host_link->additional_info" ]
  }
```