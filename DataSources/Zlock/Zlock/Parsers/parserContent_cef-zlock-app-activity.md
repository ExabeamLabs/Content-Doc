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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({app}Zlock)""",
    """msg=({activity}.+?)\s+(\w+=|$)""",
    """suser=(({domain}[^\\]+)\\)?({user}[^\s\\]+)\s+(\w+=|$)""",
    """shost=({src_host}[^\s]+)\s+(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """\srt=({time}\d+)""",
    """sproc=({process_name}[^\s]+)\s+(\w+=|$)""",
    """fsize=({file_size}\d+)""",
    """cs2=({device_name}.+?)\s+(\w+=|$)""",
    """cs3=({policy}.+?)\s+(\w+=|$)""",
    """\sdvc=({host}\S+)(\s+\w+=|\s*$)""",
    """\sdvchost=({host}\S+)(\s+\w+=|\s*$)""",
    """fname=({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^\\\/=]+?(\.({file_ext}\w+))?))\s+\w+="""
	]  
  DupFields = [ "file_name->object" ]
}
```