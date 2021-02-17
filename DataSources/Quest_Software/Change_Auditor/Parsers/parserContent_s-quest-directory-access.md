#### Parser Content
```Java
{
Name = s-quest-directory-access
  Vendor = Quest Software
  Product = Change Auditor
  Lms = Splunk
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Quest Software|ChangeAuditor""" , """art""" , """deviceSeverity""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dvc=({host}\S+)\.\s*(\w+=|$)""",
    """dvchost=({host}\S+)\s*(\w+=|$)""",
    """change for ({object_class}user|group)""",
    """sntdom=({domain}\S+)\s(\w+=|$)""",
    """categoryOutcome=({outcome}[^\s]*)\s""",
    """src=({src_ip}[^\s]+)\s*(\w+=|$)""",
    """\|({action}[^\|]*)\|(Low|Medium|High)""",
    """suser=({user_lastname}[^,]+),\s({user_firstname}([A-Za-z]+){1}(\s\w){0,1})\s""",
    """dpriv=({attribute}.+?)\s(\w+=|$)""",
    """cs1=({old_attribute}.+?)\s(\w+=|$)""",
    """cs2=({new_attribute}.+?)\s*(\w+=|$)""",
    """changed for user ({object_dn}.+?)\.\s(\w+=|$)""",
    """shost=({src_host}\S+)\s*(\w+=|$)""",
    """duser=({object}.+?)\s*(\w+=|$)"""
    """CN\\=.+?({object_ou}OU\\=.+?).\s*\w+=""",
  ]
}
```