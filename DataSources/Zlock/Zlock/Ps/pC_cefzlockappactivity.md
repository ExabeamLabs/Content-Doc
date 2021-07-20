#### Parser Content
```Java
{
Name = cef-zlock-app-activity
  Vendor = Zlock
  Product = Zlock
  DataType = "app-activity"
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""",  """|Zlock|"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({app}Zlock)""",
    """msg=({activity}.+?)\s{1,100}(\w+=|$)""",
    """suser=(({domain}[^\\]{1,2000})\\)?({user}[^\s\\]{1,2000})\s{1,100}(\w+=|$)""",
    """shost=({src_host}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """sproc=({process_name}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """fsize=({file_size}\d{1,100})""",
    """cs2=({device_name}.+?)\s{1,100}(\w+=|$)""",
    """cs3=({policy}.+?)\s{1,100}(\w+=|$)""",
    """\sdvc=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}\S+)(\s{1,100}\w+=|\s{0,100}$)""",
    """fname=({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/=]{1,2000}?(\.({file_ext}\w+))?))\s{1,100}\w+="""
	]  
  DupFields = [ "file_name->object" ]
}
```