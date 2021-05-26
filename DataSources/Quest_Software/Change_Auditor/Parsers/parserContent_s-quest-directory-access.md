#### Parser Content
```Java
{
Name = s-quest-directory-access
  Vendor = Quest Software
  Product = Change Auditor
  Lms = Splunk
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Quest Software|ChangeAuditor""" , """categoryOutcome=""" , """deviceSeverity=""", """|Custom Attribute """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """dvc=({host}\S+)\.\s{0,100}(\w+=|$)""",
    """dvchost=({host}\S+)\s{0,100}(\w+=|$)""",
    """change for ({object_class}user|group)""",
    """sntdom=({domain}\S+)\s(\w+=|$)""",
    """categoryOutcome=({outcome}[^\s]{0,2000})\s""",
    """src=({src_ip}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\|({action}[^\|]{0,2000})\|(Low|Medium|High)""",
    """suser=({user_lastname}[^,]{1,2000}),\s({user_firstname}([A-Za-z]{1,2000}){1}(\s\w){0,1})\s""",
    """dpriv=({attribute}.+?)\s(\w+=|$)""",
    """cs1=({old_attribute}.+?)\s(\w+=|$)""",
    """cs2=({new_attribute}.+?)\s{0,100}(\w+=|$)""",
    """changed for user ({object_dn}.+?)\.\s(\w+=|$)""",
    """shost=({src_host}\S+)\s{0,100}(\w+=|$)""",
    """duser=({object}.+?)\s{0,100}(\w+=|$)"""
    """CN\\=.+?({object_ou}OU\\=.+?).\s{0,100}\w+=""",
  ]
}
```