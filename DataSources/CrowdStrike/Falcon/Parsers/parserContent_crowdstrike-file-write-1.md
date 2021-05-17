#### Parser Content
```Java
{
Name = crowdstrike-file-write-1
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":""", """"DirectoryCreate"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]{1,2000})""",
      """"aid":\s{0,100}"({aid}[^"]{1,2000})""",
      """"TargetFileName":\s{0,100}"({file_path}[^"]{1,2000})""",
      """"TargetFileName":\s{0,100}"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000})""",
      """({file_type}Directory)""",
      """suser=(system|({user}[^\s]{1,2000}))""",
      """src-account-name":"({account_name}[^"]{1,2000})"""
    ]
  }
```