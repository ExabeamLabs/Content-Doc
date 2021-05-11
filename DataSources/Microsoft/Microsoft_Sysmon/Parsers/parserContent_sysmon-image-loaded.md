#### Parser Content
```Java
{
Name = sysmon-image-loaded
    Vendor = Microsoft
    Product = Microsoft Sysmon
    Lms = Direct
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """Event ID: 7""", """Image loaded:""", """ProviderName: Microsoft-Windows-Sysmon""" ]
    Fields = [
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """ComputerName(:|=)\s{0,100}({host}[\w.-]+)""",
      """UtcTime:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """User:\s{0,100}({user}.+?)\s{0,100}\w+:""",
      """ProcessGuid:\s{0,100}\{({process_guid}[^}]+?)\}""",
      """ProcessId:\s{0,100}({pid}\d{1,100})""",
      """Image:\s{0,100}({process}({directory}(\w+:)?[^:]+\\)({process_name}[^\\]+\.exe))\s{0,100}\w+:"""
      """Image:\s{0,100}({path}.+?)\s{0,100}\w+:""",
      """ImageLoaded:\s{0,100}({file_path}({file_parent}(\w+:)?[^:]+\\)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\s{0,100}\w+:""",
      """Hashes:\s{0,100}.*?MD5=({md5}[A-F0-9a-f]+)""",
      """Hashes:\s{0,100}.*?SHA256=({sha256}[A-F0-9a-f]+)""",
      """Hashes:\s{0,100}.*?IMPHASH=({imphash}[A-F0-9a-f]+)""",
      """Signed:\s{0,100}({signed}.+?)\s{0,100}\w+:"""
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```