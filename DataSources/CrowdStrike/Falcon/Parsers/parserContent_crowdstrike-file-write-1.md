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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":\s{0,100}"({time}\d{1,100})""",
      """"event_simpleName":\s{0,100}"({event_code}[^"]+)""",
      """"aid":\s{0,100}"({aid}[^"]+)""",
      """"TargetFileName":\s{0,100}"({file_path}[^"]+)""",
      """"TargetFileName":\s{0,100}"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+)""",
      """({file_type}Directory)""",
      """suser=(system|({user}[^\s]+))""",
      """src-account-name":"({account_name}[^"]+)"""
    ]
  }
```