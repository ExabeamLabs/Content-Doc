#### Parser Content
```Java
{
Name = cef-moveit-activity
  Vendor = Ipswitch
  Product = IPswitch MoveIt
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IPswitch|MoveIt|""","""dvc=""" ]
  Fields = [
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})\s\w+=""",
    """\srt=({time}\d{1,100})""",
    """\ssuser=({account_id}.+?)\s(\w+=|$)""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({dest_host}[^\s]{1,2000})\s\w+=""",
    """requestClientApplication=({browser}.+?)\s\w+=""",
    """fname=({file_name}.+?)\s\w+=""",
    """fname=[^.]{1,2000}({file_ext}.+?)\s\w+=""",
    """filePath=({file_parent}.+?)\s\w+=""",
    """fileId=({file_id}\d{1,100})\s\w+=""",
    """\s({file_type}file|File)""",
    """\|IPswitch\|MoveIt\|([^|]{0,2000}\|){2}({activity}.+?)( at \d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}|\|)""",
    """({app}MoveIt)"""
    """\smsg=({additional_info}.+?)\sart=""",
  ]
   DupFields=["file_name->object_value",
     "account_id->user",
     "browser->user_agent",
     "activity->accesses"]
}
```