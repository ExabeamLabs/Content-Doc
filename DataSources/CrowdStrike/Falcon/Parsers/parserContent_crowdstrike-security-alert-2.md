#### Parser Content
```Java
{
Name = crowdstrike-security-alert-2
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """"ExternalApiType":"Event_DetectionSummaryEvent"""", """"Severity"""", """"FalconHostLink"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"ProcessStartTime":({time}\d+)""",
      """"ComputerName":"({src_host}[^"]+)"""",
      """"UserName":"({user}[^"]+)"""",
      """"DetectName":"({alert_name}[^"]+)"""",
      """"ExternalApiType":"({alert_type}[^"]+)"""",
      """"DetectDescription":"({additional_info}[^"]+)"""",
      """"Severity":({alert_severity}\d+)""",
      """"SeverityName":"({alert_severity}[^"]+?)"""",
      """"FileName":"({file_name}[^"]+?)"""",
      """"FilePath":"({file_path}[^"]+?)\\?"""",
      """"CommandLine":"({command_line}[^,]+?)",""",
      """"CommandLine":"\\"({process}({directory}[^",]+\\\\)?({process_name}[^"\\,]+))\\"""",
      """"LocalIP":"({src_ip}[a-fA-F\d.:]+)""",
      """"RemoteAddress":"({dest_ip}[a-fA-F\d.:]+)"""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```