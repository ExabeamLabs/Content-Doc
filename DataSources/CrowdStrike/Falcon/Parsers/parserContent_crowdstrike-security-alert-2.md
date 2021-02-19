#### Parser Content
```Java
{
Name = crowdstrike-security-alert-2
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"ExternalApiType":"Event_DetectionSummaryEvent"""", """"Severity"""", """"FalconHostLink"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"ProcessStartTime":({time}\d+)""",
      """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
      """"UserName":"(N/A|({user}[^"@]+))(@({src_host}[^"]+))?"""",
      """"ComputerName":"({src_host}[^"]+)"""",
      """\\*"DetectDescription\\*":\\*"({alert_name}[^"]+?)(\.\s+|")""",
      """"DetectName":"({alert_name}[^"]+)"""",
      """"ExternalApiType":"({alert_type}[^"]+)"""",
      """"DetectDescription":"({additional_info}[^"]+)"""",
      """"Severity":({alert_severity}\d+)""",
      """"SeverityName":"({alert_severity}[^"]+?)"""",
      """"FileName":"({file_name}[^"]+?)"""",
      """"FilePath":"({file_path}[^"]+?)\\?"""",
      """"CommandLine"+:"+\\*"*({command_line}[^,"]+)\\"""",
      """"CommandLine":"\\"({process}({directory}[^",]+\\\\)?({process_name}[^"\\,]+))\\"""",
      """"LocalIP":"({src_ip}[a-fA-F\d.:]+)""",
      """"RemoteAddress":"({dest_ip}[a-fA-F\d.:]+)""",
      """"Technique":"({alert_type}[^"]+)""",
      """"LocalAddress":"({src_ip}[a-fA-F\d.:]+)""",
      """"DetectId"+:"+({alert_id}[^"]+)"""",
      """"MD5String"+:"+({md5}[^"]+)"""",
      """"SHA256String":"({sha256}[^"]+)""",
      """SensorId":"({sensor_id}[^"]+)""",
      """"GrandparentImageFileName\\*":\\*"({grandparent_image_filename}[^,]+?)\\*"+""",
      """"GrandparentCommandLine\\*"+:\s*\\*"+({grandparent_command_line}[^,]+?)\\*"+,""",
      """"ParentImageFileName\\*":\s*\\*"({parent_image_filename}[^,]+?)\\*"+,""",
      """"ParentCommandLine\\*":\s*\\*"({parent_command_line}[^,]+?)"+,""",
      """"PatternDispositionDescription\\*":\s*\\*"({pattern_disposition_description}[^"]+)""",
      """"FalconHostLink\\*":\s*\\*"({falcon_host_link}[^"]+)""",
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
    DupFields = [ "directory->process_directory", "alert_type->technique", "falcon_host_link->additional_info" ]
  }
```