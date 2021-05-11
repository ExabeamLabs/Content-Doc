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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"ProcessStartTime":({time}\d{1,100})""",
      """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
      """"UserName":"(N/A|({user}[^"@]+))(@({src_host}[^"]+))?"""",
      """"ComputerName":"({src_host}[^"]+)"""",
      """\\*"DetectDescription\\*":\\*"({alert_name}[^"]+?)(\.\s{1,100}|")""",
      """"DetectName":"({alert_name}[^"]+)"""",
      """"ExternalApiType":"({alert_type}[^"]+)"""",
      """"DetectDescription":"({additional_info}[^"]+)"""",
      """"Severity":({alert_severity}\d{1,100})""",
      """"SeverityName":"({alert_severity}[^"]+?)"""",
      """"FileName":"({file_name}[^"]+?)"""",
      """"FilePath":"({file_path}[^"]+?)\\?"""",
      """"CommandLine"{1,20}:"{1,20}\\*"{0,20}({command_line}[^,"]+?)\\*"""",
      """"CommandLine"{1,20}:"{1,20}\\*"{0,20}({process}({directory}[^",]+\\\\)?({process_name}[^"\\,]+))\\*"""",
      """"LocalIP":"({src_ip}[a-fA-F\d.:]+)""",
      """"RemoteAddress":"({dest_ip}[a-fA-F\d.:]+)""",
      """"Technique":"({alert_type}[^"]+)""",
      """"LocalAddress":"({src_ip}[a-fA-F\d.:]+)""",
      """"DetectId"{1,20}:"{1,20}({alert_id}[^"]+)"""",
      """"MD5String"{1,20}:"{1,20}({md5}[^"]+)"""",
      """"SHA256String":"({sha256}[^"]+)""",
      """SensorId":"({sensor_id}[^"]+)""",
      """"GrandparentImageFileName\\*":\\*"({grandparent_image_filename}[^,]+?)\\*"{1,20}""",
      """"GrandparentCommandLine\\*"{1,20}:\s{0,100}\\*"{1,20}({grandparent_command_line}[^,]+?)\\*"{1,20}
```