#### Parser Content
```Java
{
Name = s-crowdstrike-process-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"DetectionSummaryEvent"""", """"DetectName":""", """"Suspicious Activity"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
    """"DetectName":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"DetectDescription":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"Severity":\s{0,100}({alert_severity}[^",]{1,2000})""",
    """"DetectId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """({additional_info_1}"DocumentsAccessed":\s{0,100}[^\]]{1,2000}\]).*?({additional_info_2}"ExecutablesWritten":\s{0,100}[^\]]{1,2000}\])""",
    """"CommandLine":"({process}({directory}[^\s]{1,2000})\\\\({process_name}[^\s]{1,2000}))""",
    """"CommandLine":"\\"({process}({directory}[^"]{1,2000}?)\\{1,2}({process_name}[^\\"]{1,2000}))\\"""",
    """"FileName":\s{0,100}"({process_name}[^"]{1,2000})"""",
    """"FilePath":\s{0,100}"({file_path}[^"]{1,2000})"""",
    """"CommandLine":"({command_line}[^,]{1,2000}?)\\",""",
    """"SensorId":\s{0,100}"({sensor_id}[^"]{1,2000})"""",
    """"ComputerName":\s{0,100}"({src_host}[^"]{1,2000})"""",
    """"LocalIP":\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """"ComputerName":\s{0,100}"({src_host}[^"]{1,2000})".*?"LocalAddress":\s{0,100}"({src_ip}[^"]{1,2000})","LocalPort":\s{0,100}({src_port}\d{1,100}),"RemoteAddress":\s{0,100}"({dest_ip}[^"]{1,2000})","RemotePort":\s{0,100}({dest_port}\d{1,100}),"ConnectionDirection":\s{0,100}0""",
    """"ComputerName":\s{0,100}"({dest_host}[^"]{1,2000})".*?"LocalAddress":\s{0,100}"({dest_ip}[^"]{1,2000})","LocalPort":\s{0,100}({dest_port}\d{1,100}),"RemoteAddress":\s{0,100}"({src_ip}[^"]{1,2000})","RemotePort":\s{0,100}({src_port}\d{1,100}),"ConnectionDirection":\s{0,100}1""",
    """"MD5String":\s{0,100}"({md5}[^"]{1,2000})"""",
    """"UserName":\s{0,100}"({user}[^"]{1,2000})"""",
    """"ProcessId":({process_guid}\d{1,100})""",
    """"ParentProcessId":({parent_process_guid}\d{1,100})""",
    """"FalconHostLink":\s{0,100}"({falcon_host_link}[^"]{1,2000})"""",
    """"((?i)SHA256|SHA256String|SHA256HashData)\\*"{1,20}:\s{0,100}\\*"{1,20}({sha256}[^,]{1,2000}?)\\*"{1,20

}
```