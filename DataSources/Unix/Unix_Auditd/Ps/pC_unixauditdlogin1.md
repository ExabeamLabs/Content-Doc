#### Parser Content
```Java
{
Name = unix-auditd-login-1
  DataType = "ssh-login"
  Conditions = ["""audit_id""" , """PAM:authentication"""]

unix-auditd  = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Splunk
    TimeFormat = epoch
    Fields = [
     """time":\s{0,100}"{0,20}({time}\d{1,100})""",
     """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
     """node":\s{0,100}"({src_host}[^"]{1,2000})""",
     """object_type":\s{0,100}"({activity_type}[^"]{1,2000})""",
     """(executable|exe)":\s{0,100}"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
     """actor_primary":\s{0,100}"({user}[^"]{1,2000})""",
     """actor_secondary":\s{0,100}"({account}[^"]{1,2000})""",
     """pid":\s{0,100}({pid}[^,}\s]{1,2000})""",
     """result":\s{0,100}"({outcome}[^"]{1,2000})""",
     """op":\s{0,100}"({action}[^"]{1,2000})"""
    ] 
  },

  s-common-ftp-app-activity = {
    Vendor = FTP
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
      """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) """,
      """({host}[\w\.-]{1,2000})\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
      """({src_ip}\S+)\s{1,100}(\S+\s{1,100}){2}\[\d{1,100}\]""",
      """(-|(({domain}\S+)[\/\\])?({user}\S+))\s{1,100}\[\d{1,100}\]""",
      """\[\d{1,100}\]({activity}\w+)\s{1,100}""",
      """\[\d{1,100}\]\w+\s{1,100}({object}\S+)""",
      """\[\d{1,100}\]\w+\s{1,100}(\S+\s{1,100}){2}({outcome}\d{1,100})""",
      """\[\d{1,100}\]\w+\s{1,100}(\S+\s{1,100}){4}({bytes}\d{1,100})"""
    ]
    DupFields = [ "host->dest_host" 
}
```