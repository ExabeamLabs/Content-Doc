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
    Conditions = [ """"event_simpleName":""", """"ProcessRollup2"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"aip":\s*"({host}[^"]+)"""
      """"timestamp":\s*"({time}\d+)""",
      """"event_simpleName":\s*"({event_code}[^"]+)""",
      """"aid":\s*"({aid}[^"]+)""",
      """"CommandLine":\s*"\s*({command_line}[^,]+?)\s*"*,""",
      """"CommandLine":\s*"\s*({process}({directory}[^,="]*?[\\\/]+)({process_name}[^\\\/=]*?))\s*",""",
      """"CommandLine":\s*"\s*[^",]*"({process}({directory}[^"=]*[\\\/]+?)({process_name}[^\\\/"=]+))""",
      """"CommandLine":\s*"\s*(?=[\\\/\w.]+\s+)(({directory}[^"=]*[\\\/]+?)({process_name}[^\s"=]+))""",
      """"CommandLine":\s*"\s*(?=[\w.]+\s+)({process_name}[^\s"=]+)""",
      """"CommandLine":\s*"\s*({process}({directory}[^,="-]*?[\\\/]+)({process_name}[^\\\/=]*?))(?:\s*-+\w+.*)"+,""",
      """"CommandLine":\s*"\s*(?=\w:[\\])({process}({directory}(?:[^"=]+)?[\\])?({process_name}[^\\\/"\s=]+))""",
      """"CommandLine":\s*"\s*(?=\\"*[^\\]*\\"*)\\"*({process}({directory}(?:[^"=]+)?[\\])?({process_name}[^\\\/"\s=]+))""",
      """"ImageFileName":\s*"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
      """"id":\s*"({process_guid}[^"]+)""",
      """"MD5HashData":\s*"({md5}[^"]+)""",
      """"ParentProcessId":\s*"({parent_process_guid}[^"]+)""",
      """"TargetProcessId":\s*"({pid}[^"]+)""",
      """"UserSid":\s*"({user_sid}[^"]+)""",
      """log-severity\\=({log_severity}\S+)""",
    ]
    DupFields = [ "directory->process_directory" ]
  }
```