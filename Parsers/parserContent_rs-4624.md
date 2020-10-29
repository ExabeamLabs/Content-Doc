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
      """,\w+ ({time}\w+ \d+ \d+:\d+:\d+ \d\d\d\d),4624,""",
      """,(Audit Success|Success Audit|Information),({dest_host}[^,]+),""",
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """Logon Type:\s+({logon_type}[\d]+)""",
      """New Logon.*Account Name:\s+(-|({user}.+?))\s+(Network )?Account Domain:\s+({domain}[\w.\-]+)""",
      """Process Name:\s+(?:|(?:-|({process}({directory}.*?)(\\+({process_name}[^\\]+?))?)))\s+Network Information:""",
      """Source Network Address:\s+(?:-|({src_ip}[\w:.]+))\s+Source Port:""",
      """Logon Process:\s+({auth_process}[^\s]+)\s+Authentication Package:\s+({auth_package}[^\s]+)""",
      """Logon ID:\s+({logon_id}[^\s]+)\s+Logon GUID""",
      """New Logon:\s+Security ID:\s+({user_sid}[^\s]+)\s""",
      """Workstation Name:\s+({src_host_windows}[^\s]+)\s+Source Network"""
      """Subject:.*?Account Name:\s(-|[^\$\s]+\$|({account}[^\s]+)).*?Logon ID"""
    ]
    DupFields = [ "dest_host->host", "directory->process_directory" ]
  }
```