#### Parser Content
```Java
{
Name = crowdstrike-file-write-5
    Conditions = [ """"event_simpleName":"FsVolumeMounted"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
    """"VolumeName":"({file_path}[^"]{1,2000})""",
    """"VolumeName":"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}(\.({file_ext}[^\\\/"]{1,2000}))?)""",
    ]
  
crowdstrike-file-operations = {
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
      """"aid":\s{0,100}"({aid}[^"]{1,2000})""",
      """"SourceFileName":\s{0,100}"({src_file_dir}[^"]{1,2000}\\+)?({src_file_name}[^\\"]{1,2000})""",
      """"TargetFileName":\s{0,100}"({file_path}[^"]{1,2000})""",
      """"TargetFileName":\s{0,100}"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"\.]{1,2000}(\.({file_ext}[^\\\/"\.]{1,2000}))?)""",
      """suser=(system|({user}[^\s]{1,2000}))""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
      """"((?i)SHA256String|SHA256HashData)":"({sha256}[^"]{1,2000})"""",
      """"name":"({event_name}[^"]{1,2000})"""",
      """UserName":"({user}[^"]{1,2000})"""",
      """"ContextProcessId":"({process_guid}[^"]{1,2000})"""",
      """"aip":"({src_ip}[a-fA-F\d:.]{1,2000})""""
    
}
```