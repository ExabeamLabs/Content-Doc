#### Parser Content
```Java
{
Name = rs-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ ",4624,Microsoft-Windows-Security-Auditing", "Logon Type", "An account was successfully logged on" ]
    Fields = [
      """exabeam_host=({dest_host}[\w.\-]+)""",
      """,\w+ ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d\d\d\d),4624,""",
      """,(Audit Success|Success Audit|Information),({dest_host}[^,]+),""",
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """Logon Type:\s{1,100}({logon_type}[\d]+)""",
      """New Logon.*Account Name:\s{1,100}(-|({user}.+?))\s{1,100}(Network )?Account Domain:\s{1,100}({domain}[\w.\-]+)""",
      """Process Name:\s{1,100}(?:|(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]+?))?)))\s{1,100}Network Information:""",
      """Source Network Address:\s{1,100}(?:-|({src_ip}[\w:.]+))\s{1,100}Source Port:""",
      """Logon Process:\s{1,100}({auth_process}[^\s]+)\s{1,100}Authentication Package:\s{1,100}({auth_package}[^\s]+)""",
      """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}Logon GUID""",
      """New Logon:\s{1,100}Security ID:\s{1,100}({user_sid}[^\s]+)\s""",
      """Workstation Name:\s{1,100}({src_host_windows}[^\s]+)\s{1,100}Source Network"""
      """Workstation Name:\s{1,100}({src_host_windows}[^\s]+)\s{1,100}Source Network""",
      """Key Length:\s{0,100}({key_length}\d{1,100})"""
    ]
    DupFields = [ "dest_host->host", "directory->process_directory" ]
  }
```