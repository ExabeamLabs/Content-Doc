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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":"({time}\d{1,100})""",
      """requestClientApplication=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
      """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"event_simpleName":"({event_code}[^"]{1,2000})"""",
      """"TargetFileName":"({file_parent}[^"]{0,2000}[\\\/]{1,2000})({file_name}[^\\\/"]{1,2000}(\.({file_ext}[^\\\/"]{1,2000})))"""",
      """"TargetFileName":"({file_path}[^"]{1,2000})"""",
      """"FileObject":"({object}[^"]{1,2000})"""",
      """"aid":"({aid}[^"]{1,2000})""""
    ]
  

}
```