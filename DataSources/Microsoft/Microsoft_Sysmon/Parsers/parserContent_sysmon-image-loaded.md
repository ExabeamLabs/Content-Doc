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
      """Event ID:\s*({event_code}\d+)""",
      """ComputerName(:|=)\s*({host}[\w.-]+)""",
      """UtcTime:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """User:\s*({user}.+?)\s*\w+:""",
      """ProcessGuid:\s*\{({process_guid}[^}]+?)\}""",
      """ProcessId:\s*({pid}\d+)""",
      """Image:\s*({process}({directory}(\w+:)?[^:]+\\)({process_name}[^\\]+\.exe))\s*\w+:"""
      """Image:\s*({path}.+?)\s*\w+:""",
      """ImageLoaded:\s*({file_path}({file_parent}(\w+:)?[^:]+\\)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\s*\w+:""",
      """Hashes:\s*.*?MD5=({md5}[A-F0-9a-f]+)""",
      """Hashes:\s*.*?SHA256=({sha256}[A-F0-9a-f]+)""",
      """Hashes:\s*.*?IMPHASH=({imphash}[A-F0-9a-f]+)""",
      """Signed:\s*({signed}.+?)\s*\w+:"""
    ]
    DupFields = [ "host->dest_host","directory->process_directory" ]
  }
```