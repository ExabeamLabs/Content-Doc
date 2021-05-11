#### Parser Content
```Java
{
Name = rs-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ ",4625,Microsoft-Windows-Security-Auditing", "Logon Type", "An account failed to log on" ]
    Fields = [
      """({event_name}An account failed to log on)""",
      """exabeam_host=({dest_host}[\w.\-]+)""",
      """,\w+ ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d\d\d\d),4625,""",
      """,(Audit Failure|Failure Audit|Information),({dest_host}[^,]+),""",
      """({event_code}4625)""",
      """\s{0,100}Subject:.+?Account Name:\s{1,100}(?=\w)(-|({caller_user}[^\s@]+?))[\s;]*Account Domain:""",
      """\s{0,100}Subject:.+?Account Domain:\s{1,100}(?=\w)({caller_domain}[^:;]+?)[\s;]*Failure Information:""",
      """Logon Type:\s{1,100}({logon_type}[\d]+)""",
      """Logon Process:\s{1,100}(?:({auth_process}[^\s]+))\s{1,100}Authentication Package:""",
      """Authentication Package:\s{1,100}(?:({auth_package}[^\s]+))\s{1,100}Transited Services""",
      """Logon ID:\s{1,100}({logon_id}[^\s]+)\s{1,100}Logon GUID""",
      """\s{0,100}Account For[\s;]*Which Logon Failed:[\s;]*Security ID:\s{0,100}(?:\/?NULL SID|(?:|({user_sid}.+?)))[\s;]*Account Name""",
      """\s{0,100}Logon Failed:.+?Account Name:\s{0,100}(?=\w)({user}[^\s@]+?)[\s;]*Account Domain:""",
      """\s{0,100}Logon Failed:.+?Account Domain:\s{0,100}(?=\w)({domain}.+?)[\s;]*Failure Information""",
      """\s{0,100}Sub Status:\s{0,100}({result_code}.+?)[\s;]*Process Information:""",
      """Workstation Name:\s{1,100}({src_host_windows}[^\s]+)\s{1,100}Source Network""",
      """Source Network Address:\s{1,100}(?:-|({src_ip}[\w:.]+))\s{1,100}Source Port:"""
      """Key Length:\s{0,100}({key_length}\d{1,100})"""
    ]
    DupFields = [ "dest_host->host", "src_host_windows->src_host" ]
  }
```