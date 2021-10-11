#### Parser Content
```Java
{
Name = r-nic-4771
  Vendor = Microsoft
  Product = Windows
  Lms = RsaSa
  DataType = "windows-4771"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Kerberos pre-authentication failed", ",4771,Microsoft-Windows-Security-Auditing", "rsa_sa_log" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
    """Security,(rn=)?({record_id}[\d]{1,2000})""",
    """Failure Audit,({host}[^,]{1,2000})""",
    """\d{2}:\d{2}:\d{2} \d{4},({event_code}[^,]{1,2000}),Microsoft-Windows-Security-Auditing""",
    """Account Information:\s{1,100}Security ID:\s{1,100}({user_sid}.+?)\s{1,100}Account""",
    """Account Name:\s{1,100}({user}.+?)\s{1,100}Service Information""",
    """Service Name:\s{1,100}\w+\/(?=\w)({domain}.+?)\s{1,100}Network Information""",
    """Client Address:\s{1,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """Failure Code:\s{1,100}({result_code}[\w]{1,2000})"""
  ]
}
```