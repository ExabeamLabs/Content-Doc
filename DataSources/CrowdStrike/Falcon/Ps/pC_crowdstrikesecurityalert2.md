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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"ProcessStartTime":({time}\d{1,100})""",
      """({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
      """"UserName":"(N/A|({user}[^"@]{1,2000}))(@({src_host}[^"]{1,2000}))?"""",
      """"ComputerName":"({src_host}[^"]{1,2000})"""",
      """\\*"DetectDescription\\*":\\*"({alert_name}[^"]{1,2000}?)(\.\s{1,100}|")""",
      """"DetectName":"({alert_name}[^"]{1,2000})"""",
      """"ExternalApiType":"({alert_type}[^"]{1,2000})"""",
      """"DetectDescription":"({additional_info}[^"]{1,2000})"""",
      """"Severity":({alert_severity}\d{1,100})""",
      """"SeverityName":"({alert_severity}[^"]{1,2000}?)"""",
      """"FileName":"({file_name}[^"]{1,2000}?)"""",
      """"FilePath":"({file_path}[^"]{1,2000}?)\\?"""",
      """"CommandLine"{1,20}:"{1,20}\\*"{0,20}({command_line}[^,"]{1,2000}?)\\*"""",
      """"CommandLine"{1,20}:"{1,20}\\*"{0,20}({process}({directory}[^",]{1,2000}\\\\)?({process_name}[^"\\,]{1,2000}))\\*"""",
      """"LocalIP":"({src_ip}[a-fA-F\d.:]{1,2000})""",
      """"RemoteAddress":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """"Technique":"({alert_type}[^"]{1,2000})""",
      """"LocalAddress":"({src_ip}[a-fA-F\d.:]{1,2000})""",
      """"DetectId"{1,20}:"{1,20}({alert_id}[^"]{1,2000})"""",
      """"MD5String"{1,20}:"{1,20}({md5}[^"]{1,2000})"""",
      """"SHA256String":"({sha256}[^"]{1,2000})""",
      """SensorId":"({sensor_id}[^"]{1,2000})""",
      """"GrandparentImageFileName\\*":\\*"({grandparent_image_filename}[^,]{1,2000}?)\\*"{1,20}""",
      """"GrandparentCommandLine\\*"{1,20}:\s{0,100}\\*"{1,20}({grandparent_command_line}[^,]{1,2000}?)\\*"{1,20}
```