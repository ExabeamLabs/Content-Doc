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
      """"CommandLine"+:\s*"+\\*"*({command_line}[^,"]+)\\"""",
      """"CommandLine":\s*"\\"({process}({directory}[^",]+\\\\)?({process_name}[^"\\,]+))\\"""",
      """"LocalIP":\s*"({src_ip}[a-fA-F\d.:]+)""",
      """"RemoteAddress":\s*"({dest_ip}[a-fA-F\d.:]+)""",
      """\\*"DetectDescription\\*":\s*\\*"({alert_name}[^"]+)""",
      """"DetectName":\s*"({alert_name}[^"]+)""",
      """"Technique":\s*"({alert_type}[^"]+)""",
      """"LocalAddress":\s*"({src_ip}[^"]+)""",
      """"DetectId"+:\s*"+({alert_id}[^"]+)"""",
      """"MD5String"+:\s*"+({md5}[^"]+)"""",
      """"SHA256String":\s*"({sha256}[^"]+)"""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```