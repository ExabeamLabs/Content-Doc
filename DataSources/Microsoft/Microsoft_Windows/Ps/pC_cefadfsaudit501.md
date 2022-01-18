#### Parser Content
```Java
{
Name = cef-ad-fs-audit-501
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|AD FS Auditing:501""" ]

cef-ad-fs-audit = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sexternalId=({event_code}\d{1,100})""",
    """\sdhost=({dest_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sahost=({src_host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdvc=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sdeviceSeverity=({outcome}\w+)""",
    """\scs5=({user_email}[^@=\s]{1,2000}@[^@=\s\-]{1,2000})""",
    """\scs5=({domain}[^\\=]{1,2000})\\+({user}[^\\=]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\sduser=(NETWORK SERVICE|({user}.+?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """CEF:([^\|]{0,2000}\|){5}({failure_reason}[^\|]{1,2000}).*Audit_failure""",
    """Audit_failure.*\scs5=[^=\-]{0,2000}?-(|({failure_reason}.+?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
  
}
```