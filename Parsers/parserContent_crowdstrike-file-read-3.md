#### Parser Content
```Java
{
Name = crowdstrike-file-read-3
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "file-read"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"RansomwareOpenFile"""", """"timestamp":"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """requestClientApplication=({app}[^=]+?)\s*\w+=""",
      """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"event_simpleName":"({event_name}[^"]+)"""",
      """"TargetFileName":"({file_parent}[^"]*[\\\/]+)({file_name}[^\\\/"]+(\.({file_ext}[^\\\/"]+)))"""",
      """"TargetFileName":"({file_path}[^"]+)"""",
      """"FileObject":"({object}[^"]+)"""",
      """"aid":"({aid}[^"]+)""""
    ]
  }
```