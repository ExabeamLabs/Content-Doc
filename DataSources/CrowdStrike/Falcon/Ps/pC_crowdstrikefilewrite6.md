#### Parser Content
```Java
{
Name = crowdstrike-file-write-6
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"CriticalFileModified"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":"({time}\d{1,100})"""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"TargetFileName":"({file_path}[^"]{1,2000})""",
      """"TargetFileName":"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000})""",
      """({accesses}Modified)"""
    ]
  

}
```