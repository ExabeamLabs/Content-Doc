#### Parser Content
```Java
{
Name = crowdstrike-file-download-1
    Conditions = [ """"event_simpleName":"LFODownloadConfirmation"""" ]
    Fields = ${CrowdStrikeParserTemplates.crowdstrike-file-operations.Fields} [
      """"{1,20}aip"{1,20}:"{1,20}({src_ip}[A-za-z0-9.\d:]{1,2000})""",
      """DownloadPath"{1,20}:"{1,20}({file_path}[^"]{1,2000})""",
      """DownloadPort"{1,20}:"{1,20}({dest_port}[^"]{1,2000})""",
      """DownloadServer"{1,20}:"{1,20}({dest_host}[^"]{1,2000})""",
      """"ConfigStateHash":"({old_hash}[^"]{1,2000})""",
      """"SHA256HashData":"({new_hash}[^"]{1,2000})""",
    ]
  }
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
      """"TargetFileName":\s{0,100}"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}\.({file_ext}[^\\\/"]{1,2000}))""",
      """suser=(system|({user}[^\s]{1,2000}))""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
      """"((?i)SHA256String|SHA256HashData)":"({sha256}[^"]{1,2000})""""
    ]

```