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
      """SensorId":"({sensor_id}[^"]+)"""
    ]
    DupFields = [ "directory->process_directory", "alert_type->technique" ]
  }
```