#### Parser Content
```Java
{
Name = raw-4624
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""An account was successfully logged on""", """Account Name:"""]
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s({host}[\w\-.]{1,2000})?""",
      """\d\d:\d\d:\d\d(\+|-)\d\d:\d\d\s({host}[^\s]{1,2000})""",
      """(?i)<\d{1,100}>\s{0,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(am|pm|({host}[\w.\-]{1,2000}))""",
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """Logon Type:\s{0,100}({logon_type}[\d]{1,2000})""",
      """New Logon[^=]{0,2000}?Account Name:\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain""",
      """New Logon[^=]{0,2000}?Account Domain:\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID""",
      """Process Name:\s{0,100}(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]{1,2000}?))?))\s{1,100}Network Information""",
      """Workstation Name:\s{0,100}(-|[A-Fa-f:\d.]{1,2000}|({src_host_windows}[^\s;]{1,2000}))[\s;]{0,2000}Source Network Address""",
      """Source Network Address:\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))[\s;]{0,2000}Source Port""",
      """Logon Process:\s{0,100}({auth_process}[^\s;]{1,2000})[\s;]{0,2000}Authentication Package:\s{0,100}({auth_package}[^\s;]{1,2000})""",
      """Logon ID:\s{0,100}({logon_id}[^\s;]{1,2000})[\s;]{0,2000}(Linked Logon|Logon GUID)""",
      """New Logon:[\s;]{0,2000}Security ID:\s{0,100}({user_sid}[^;:]{1,2000}?)(\s{1,100}|;)Account Name:""",
      """Key Length(:|=)\s{0,100}({key_length}\d{1,100})"""
      """Subject(:|=)[\s;]{0,2000}Security ID(:|=)\s{0,100}({subject_sid}[^;:=]{1,2000}?)(\s{1,100}|;)Account Name(:|=)"""
    ]
    DupFields = ["directory->process_directory"]
  

}
```