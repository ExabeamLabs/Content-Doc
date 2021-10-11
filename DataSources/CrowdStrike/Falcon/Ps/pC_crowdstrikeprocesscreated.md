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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"aip":\s{0,100}"({host}[^"]{1,2000})""",
      """"aip":\s{0,100}"({dest_ip}[^"]{1,2000})"""
      """"timestamp":\s{0,100}"({time}\d{1,100})"""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
      """"aid":\s{0,100}"({aid}[^"]{1,2000})""",
      """"CommandLine":\s{0,100}"\s{0,100}({command_line}[^\n]{1,2000}?)\s{0,100}"?,"""",
      """"CommandLine":\s{0,100}"\s{0,100}({process}({directory}[^,="]{0,2000}?[\\\/]{1,2000})({process_name}[^\\\/=]{0,2000}?))\s{0,100}",""",
      """"CommandLine":\s{0,100}"\s{0,100}[^",]{0,2000}"({process}({directory}[^"=]{0,2000}[\\\/]{1,2000}?)({process_name}[^\\\/"=]{1,2000}))""",
      """"CommandLine":\s{0,100}"\s{0,100}(?=[\\\/\w.]{1,2000}\s{1,100})(({directory}[^"=]{0,2000}[\\\/]{1,2000}?)({process_name}[^\s"=]{1,2000}))""",
      """"CommandLine":\s{0,100}"\s{0,100}(?=[\w.]{1,2000}\s{1,100})({process_name}[^\s"=]{1,2000})""",
      """"CommandLine":\s{0,100}"\s{0,100}({process}({directory}[^,="-]{0,2000}?[\\\/]{1,2000})({process_name}[^\\\/=]{0,2000}?))(?:\s{0,100}-+\w+.*)"{1,20},""",
      """"CommandLine":\s{0,100}"\s{0,100}(?=\w:[\\])({process}({directory}(?:[^"=]{1,2000})?[\\])?({process_name}[^\\\/"\s=]{1,2000}))""",
      """"CommandLine":\s{0,100}"\s{0,100}(?=\\"{0,20}[^\\]{0,2000}\\"{0,20})\\"{0,20}({process}({directory}(?:[^"=]{1,2000})?[\\])?({process_name}[^\\\/"\s=]{1,2000}))""",
      """"ImageFileName":\s{0,100}"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
      """"id":\s{0,100}"({process_guid}[^"]{1,2000})""",
      """"MD5HashData":\s{0,100}"({md5}[^"]{1,2000})""",
      """"ParentProcessId":\s{0,100}"({parent_process_guid}[^"]{1,2000})""",
      """"TargetProcessId":\s{0,100}"({pid}[^"]{1,2000})""",
      """"UserSid":\s{0,100}"({user_sid}[^"]{1,2000})""",
      """log-severity\\=({log_severity}\S+)""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
      """"((?i)SHA256String|SHA256HashData)":"({sha256}[^"]{1,2000})"""",
      """ParentBaseFileName":"({file_name}[^"]{1,2000})"""",
      """"ContextProcessId":"({process_guid}[^"]{1,2000})"""",
      """"ParentBaseFileName":"({parent_process}[^"]{1,2000})"""",
      """"GrandParentBaseFileName":"({grandparent_process}[^"]{1,2000})""""
    ]
    DupFields = [ "directory->process_directory" ]
  }
```