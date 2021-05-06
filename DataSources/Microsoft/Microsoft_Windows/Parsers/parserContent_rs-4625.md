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
      """,\w+ ({time}\w+ \d+ \d+:\d+:\d+ \d\d\d\d),4625,""",
      """,(Audit Failure|Failure Audit|Information),({dest_host}[^,]+),""",
      """({event_code}4625)""",
      """\s*Subject:.+?Account Name:\s+(?=\w)(-|({caller_user}[^\s@]+?))[\s;]*Account Domain:""",
      """\s*Subject:.+?Account Domain:\s+(?=\w)({caller_domain}[^:;]+?)[\s;]*Failure Information:""",
      """Logon Type:\s+({logon_type}[\d]+)""",
      """Logon Process:\s+(?:({auth_process}[^\s]+))\s+Authentication Package:""",
      """Authentication Package:\s+(?:({auth_package}[^\s]+))\s+Transited Services""",
      """Logon ID:\s+({logon_id}[^\s]+)\s+Logon GUID""",
      """\s*Account For[\s;]*Which Logon Failed:[\s;]*Security ID:\s*(?:\/?NULL SID|(?:|({user_sid}.+?)))[\s;]*Account Name""",
      """\s*Logon Failed:.+?Account Name:\s*(?=\w)({user}[^\s@]+?)[\s;]*Account Domain:""",
      """\s*Logon Failed:.+?Account Domain:\s*(?=\w)({domain}.+?)[\s;]*Failure Information""",
      """\s*Sub Status:\s*({result_code}.+?)[\s;]*Process Information:""",
      """Workstation Name:\s+({src_host_windows}[^\s]+)\s+Source Network""",
      """Source Network Address:\s+(?:-|({src_ip}[\w:.]+))\s+Source Port:"""
      """Key Length:\s*({key_length}\d+)"""
    ]
    DupFields = [ "dest_host->host", "src_host_windows->src_host" ]
  }
```