#### Parser Content
```Java
{
Name = crowdstrike-process-created
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "process-created"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"""", """ProcessRollup2"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """({host}[\w\-.]+)\s+Skyformation""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"CommandLine":"\s*({command_line}[^,]+?)\s*"*,""",
      """"CommandLine":"\s*({process}({directory}[^,="]*?[\\\/]+)({process_name}[^\\\/=]*?))\s*",""",
      """"CommandLine":"\s*[^",]*"({process}({directory}[^"=]*[\\\/]+?)({process_name}[^\\\/"=]+))""",
      """"CommandLine":"\s*(?=[\\\/\w.]+\s+)(({directory}[^"=]*[\\\/]+?)({process_name}[^\s"=]+))""",
      """"CommandLine":"\s*(?=[\w.]+\s+)({process_name}[^\s"=]+)""",
      """"CommandLine":"\s*({process}({directory}[^,="-]*?[\\\/]+)({process_name}[^\\\/=]*?))(?:\s*-+\w+.*)"+,""",
      """"CommandLine":"\s*(?=\w:[\\])({process}({directory}(?:[^"=]+)?[\\])?({process_name}[^\\\/"\s=]+))""",
      """"CommandLine":"\s*(?=\\"*[^\\]*\\"*)\\"*({process}({directory}(?:[^"=]+)?[\\])?({process_name}[^\\\/"\s=]+))""",
      """"id":"({process_guid}[^"]+)""",
      """"MD5HashData":"({md5}[^"]+)""",
      """"ParentProcessId":"({parent_process_guid}[^"]+)""",
      """"TargetProcessId":"({pid}[^"]+)""",
      """"UserSid":"({user_sid}[^"]+)""",
      """log-severity\\=({log_severity}\S+)""",
    ]
    DupFields = [ "directory->process_directory" ]
  }
```