#### Parser Content
```Java
{
Name = q-crowdstrike-process-alert-1
  Vendor = CrowdStrike
  Product = Falcon
  Lms = QRadar
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Suspicious Activity""", """|CrowdStrikeDetection|""", """CrowdStrike-UserName =""", """CrowdStrike-MD5""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """srcPreNAT=({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """({event_name}CrowdStrike Detection)""",
    """({alert_name}Suspicious Activity)""",
    """CrowdStrike-Severity=({alert_severity}[^\s]{1,2000})""",
    """CrowdStrike-DetectId=({alert_id}[^\s]{1,2000})""",
    """CrowdStrike-CommandLine="{1,100}({command_line}({process_directory}[^\.]{1,2000})[\\\/][^"]{1,2000})""",
    """CrowdStrike-FilePath=({file_path}[^\s]{1,2000})""",
    """CrowdStrike-FileName =({process_name}[^\=]{1,2000}?)(\s+CrowdStrike-SensorId)""",
    """CrowdStrike-ComputerName =({src_host}[^\s]{1,2000})""",
    """CrowdStrike-IOCValue=({file_hash}[^\s]{1,2000})""",
    """CrowdStrike-UserName =(N/A|({user}[^\s]{1,2000}))""",
    """CrowdStrike-ProcessId=({process_guid}\d{1,100})""",
    """CrowdStrike-FalconHostLink=({falcon_host_link}[^\s]{1,2000})""",
    """CrowdStrike-MD5=({md5}[^\s]{1,2000})""",
 ]
   DupFields = ["falcon_host_link->additional_info","command_line->process"]


}
```